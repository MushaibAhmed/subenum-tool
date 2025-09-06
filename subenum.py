#!/usr/bin/env python3
"""
subenum.py
Pipeline:
1) brute-force + API collectors -> gather candidate subdomains
2) resolve and check liveness (http/tcp)
3) extract IPs, classify (private vs public)
4) query Shodan for public IPs -> ports + CVEs

Includes an ASCII banner (team name) displayed at start.
"""
import argparse, asyncio, aiohttp, json, sys, time
from concurrent.futures import ThreadPoolExecutor
import dns.resolver, socket
import ipaddress
import shodan
from typing import List, Dict, Set, Tuple
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()  # allow API keys in .env too

# ---------- CONFIG (environment fallback) ----------
VT_API = os.getenv("VT_API")      # optional VirusTotal API key
ST_API = os.getenv("ST_API")      # optional SecurityTrails API key
SHODAN_API = os.getenv("SHODAN_API")  # optional Shodan API key

# ---------- OPTIONAL BANNER HELPERS ----------
def print_banner(team_name: str = "Cyber Hunters", font: str = "slant", use_color: bool = True):
    """
    Try to print a nice ASCII banner using pyfiglet and colorama if available.
    Falls back to plain text if libraries are missing.
    """
    banner_text = None
    try:
        import pyfiglet
        banner_text = pyfiglet.figlet_format(team_name, font=font)
    except Exception:
        banner_text = f"=== {team_name} ===\\n"

    # colorize if colorama available and requested
    if use_color:
        try:
            from colorama import Fore, Style, init as color_init
            color_init(autoreset=True)
            print(Fore.CYAN + banner_text + Style.RESET_ALL)
            print("=" * 70)
            return
        except Exception:
            pass

    print(banner_text)
    print("=" * 70)


# ---------- UTIL ----------
def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except Exception:
        return False

# ---------- COLLECTORS ----------
async def vt_subdomains(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    """VirusTotal v3: /domains/{domain}/subdomains (requires key)."""
    if not api_key:
        return set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}
    subs = set()
    try:
        async with session.get(url, headers=headers, timeout=20) as resp:
            if resp.status != 200:
                return subs
            data = await resp.json()
            for item in data.get("data", []):
                # vt may return id like "sub.example.com"
                name = item.get("id") or item.get("attributes", {}).get("name")
                if name and name.endswith(domain):
                    subs.add(name)
    except Exception:
        pass
    return subs

async def st_subdomains(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    """SecurityTrails v1: /v1/domain/{domain}/subdomains (requires key)."""
    if not api_key:
        return set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    subs = set()
    try:
        async with session.get(url, headers=headers, params={"children_only": False}, timeout=20) as resp:
            if resp.status != 200:
                return subs
            data = await resp.json()
            # ST returns list of subdomain fragments; append domain to get FQDN
            for s in data.get("subdomains", []):
                fqdn = f"{s}.{domain}"
                subs.add(fqdn)
    except Exception:
        pass
    return subs

def brute_force_from_wordlist(domain: str, wordlist_path: str, max_entries: int = 200000) -> Set[str]:
    subs = set()
    p = Path(wordlist_path)
    if not p.exists():
        return subs
    with p.open("r", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if i >= max_entries:
                break
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            subs.add(f"{w}.{domain}")
    return subs

# ---------- RESOLUTION ----------
def resolve_name(name: str, resolver=None, timeout=5) -> List[str]:
    """Resolve A and AAAA (blocking)"""
    ips = set()
    try:
        r = resolver or dns.resolver.Resolver()
        r.lifetime = timeout
        try:
            ans = r.resolve(name, "A", lifetime=timeout)
            for rr in ans:
                ips.add(rr.to_text())
        except Exception:
            pass
        try:
            ans = r.resolve(name, "AAAA", lifetime=timeout)
            for rr in ans:
                ips.add(rr.to_text())
        except Exception:
            pass
    except Exception:
        pass
    return list(ips)

# ---------- LIVENESS CHECK ----------
async def http_check(session: aiohttp.ClientSession, url: str, timeout=6) -> bool:
    try:
        async with session.head(url, timeout=timeout, allow_redirects=True) as r:
            return r.status < 400
    except Exception:
        # try GET as fallback
        try:
            async with session.get(url, timeout=timeout, allow_redirects=True) as r2:
                return r2.status < 400
        except Exception:
            return False

async def tcp_port_open(ip: str, port: int, timeout=3) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def is_live(subdomain: str, resolved_ips: List[str], session: aiohttp.ClientSession, timeout=6) -> Tuple[bool, str]:
    # Try HTTPS then HTTP (SNI). If resolved_ips empty, skip to failure
    schemes = ["https://", "http://"]
    for s in schemes:
        url = s + subdomain
        ok = await http_check(session, url, timeout=timeout)
        if ok:
            return True, f"{s}"
    # fallback: try TCP connect on common ports to each resolved IP
    common_ports = [443, 80]
    for ip in resolved_ips:
        for p in common_ports:
            if await tcp_port_open(ip, p, timeout=3):
                return True, f"tcp:{ip}:{p}"
    return False, ""

# ---------- SHODAN ----------
def shodan_query(api_key: str, ip: str) -> Dict:
    if not api_key:
        return {}
    try:
        sh = shodan.Shodan(api_key)
        info = sh.host(ip)  # may raise shodan.APIError
        ports = info.get("ports", [])
        vulns = info.get("vulns") or info.get("vulnerability") or []
        return {"ports": ports, "vulns": vulns, "raw": info}
    except Exception as e:
        return {"error": str(e)}

# ---------- MAIN PIPELINE ----------
async def run_pipeline(domain: str, wordlist: str, vt_key: str, st_key: str, shodan_key: str,
                       threads: int = 50, timeout: int = 6, out_file: str = None):
    start = time.time()
    candidates = set()

    # 1) bruteforce
    if wordlist:
        print("[*] Running brute-force wordlist...")
        bf = brute_force_from_wordlist(domain, wordlist)
        print(f"[+] Bruteforce produced {len(bf)} candidates")
        candidates |= bf

    # 2) API collectors (async)
    async with aiohttp.ClientSession() as session:
        api_tasks = []
        if vt_key:
            api_tasks.append(vt_subdomains(session, domain, vt_key))
        if st_key:
            api_tasks.append(st_subdomains(session, domain, st_key))
        if api_tasks:
            print("[*] Querying APIs...")
            results = await asyncio.gather(*api_tasks)
            for r in results:
                candidates |= r
            print(f"[+] Total candidates after APIs: {len(candidates)}")

        # dedupe & normalize
        candidates = {c.lower().strip() for c in candidates if c and c.endswith(domain)}
        candidate_list = list(candidates)  # preserve fixed order for task mapping

        # 3) Resolve concurrently using ThreadPool
        print("[*] Resolving candidate names (A/AAAA)...")
        resolver = dns.resolver.Resolver()
        loop = asyncio.get_running_loop()
        resolved_map = {}  # sub -> [ips]
        with ThreadPoolExecutor(max_workers=threads) as pool:
            tasks = []
            for name in candidate_list:
                tasks.append(loop.run_in_executor(pool, resolve_name, name, resolver, timeout))
            reslist = await asyncio.gather(*tasks)
        for name, ips in zip(candidate_list, reslist):
            if ips:
                resolved_map[name] = ips

        print(f"[+] Resolved {len(resolved_map)} names to IP(s)")

        # 4) Liveness check (async)
        print("[*] Checking if resolved names are live (http/tcp)...")
        live_map = {}  # sub -> {"ips":[], "live":True, "how": "..."}
        sem = asyncio.Semaphore(200)
        async def check_one(sub, ips):
            async with sem:
                ok, how = await is_live(sub, ips, session, timeout=timeout)
                return sub, ok, how

        check_tasks = [check_one(s, ips) for s, ips in resolved_map.items()]
        results = await asyncio.gather(*check_tasks)
        for sub, ok, how in results:
            if ok:
                live_map[sub] = {"ips": resolved_map.get(sub, []), "how": how}

        print(f"[+] {len(live_map)} live subdomains")

        # 5) Classify IPs and run Shodan for public IPs
        aggregated = {}
        public_ips = set()
        for sub, info in live_map.items():
            ips = info["ips"]
            priv = [ip for ip in ips if is_private_ip(ip)]
            pub = [ip for ip in ips if not is_private_ip(ip)]
            for ip in pub:
                public_ips.add(ip)
            aggregated[sub] = {"ips": ips, "private": priv, "public": pub, "how": info["how"]}

        shodan_results = {}
        if shodan_key and public_ips:
            print("[*] Querying Shodan for public IPs...")
            # run in threadpool (shodan lib is sync)
            with ThreadPoolExecutor(max_workers=10) as pool:
                futs = [loop.run_in_executor(pool, shodan_query, shodan_key, ip) for ip in public_ips]
                sh_res = await asyncio.gather(*futs)
            for ip, r in zip(list(public_ips), sh_res):
                shodan_results[ip] = r

        # prepare final report
        report = {"domain": domain, "timestamp": int(time.time()), "subdomains": aggregated, "shodan": shodan_results}
        if out_file:
            with open(out_file, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[+] Wrote report to {out_file}")
        else:
            print(json.dumps(report, indent=2))

    print(f"[+] Done in {time.time()-start:.1f}s")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Subdomain enumeration pipeline with banner")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("-w", "--wordlist", default=None, help="Path to wordlist for bruteforce")
    p.add_argument("--vt-key", default=None, help="VirusTotal API key (optional)")
    p.add_argument("--st-key", default=None, help="SecurityTrails API key (optional)")
    p.add_argument("--shodan-key", default=None, help="Shodan API key (optional)")
    p.add_argument("--threads", type=int, default=50, help="Resolver threadpool size")
    p.add_argument("--timeout", type=int, default=6, help="Network timeout seconds")
    p.add_argument("-o", "--out", default=None, help="Write JSON output to file")
    # banner options
    p.add_argument("--team", default="Cyber Hunters", help="Team name to display in banner")
    p.add_argument("--font", default="slant", help="pyfiglet font for banner (e.g. slant, block, digital)")
    p.add_argument("--no-color", action="store_true", help="Disable colored banner output")
    args = p.parse_args()

    # prefer CLI args, fallback to environment
    vt = args.vt_key or VT_API
    st = args.st_key or ST_API
    sh = args.shodan_key or SHODAN_API

    # print banner
    print_banner(team_name=args.team, font=args.font, use_color=(not args.no_color))

    try:
        asyncio.run(run_pipeline(args.domain, args.wordlist, vt, st, sh, args.threads, args.timeout, args.out))
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(1)
