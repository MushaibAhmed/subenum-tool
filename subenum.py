#!/usr/bin/env python3
"""
subenum.py
Subdomain Enumeration Tool v0.1.1
"""

import argparse, asyncio, aiohttp, json, sys, time
from concurrent.futures import ThreadPoolExecutor
import dns.resolver, ipaddress, shodan, os
from pathlib import Path
from dotenv import load_dotenv
from typing import Set, List, Dict, Tuple

# ---------------- ANSI COLORS ----------------
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# ---------------- ENVIRONMENT ----------------
load_dotenv()
VT_API = os.getenv("VT_API")
ST_API = os.getenv("ST_API")
SHODAN_API = os.getenv("SHODAN_API")

# ---------------- BANNER ----------------
def print_banner(team_name="Cyber Hunters", font="slant"):
    try:
        import pyfiglet
        banner_text = pyfiglet.figlet_format(team_name, font=font)
    except Exception:
        banner_text = f"=== {team_name} ===\n"
    print(CYAN + banner_text + RESET)
    print(YELLOW + "="*80 + RESET)
    print(f"{GREEN}Subdomain Enumeration Tool v0.1.1")
    print(f"Author: TEAM CYBER HUNTERS{RESET}")
    print(YELLOW + "="*80 + RESET + "\n")

# ---------------- UTIL ----------------
def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except Exception:
        return False

# ---------------- COLLECTORS ----------------
async def vt_subdomains(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    if not api_key: return set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}
    subs = set()
    try:
        async with session.get(url, headers=headers, timeout=20) as resp:
            if resp.status != 200: return subs
            data = await resp.json()
            for item in data.get("data", []):
                name = item.get("id") or item.get("attributes", {}).get("name")
                if name and name.endswith(domain): subs.add(name)
    except: pass
    return subs

async def st_subdomains(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    if not api_key: return set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    subs = set()
    try:
        async with session.get(url, headers=headers, params={"children_only": False}, timeout=20) as resp:
            if resp.status != 200: return subs
            data = await resp.json()
            for s in data.get("subdomains", []):
                fqdn = f"{s}.{domain}"
                subs.add(fqdn)
    except: pass
    return subs

def brute_force_from_wordlist(domain: str, wordlist_path: str, max_entries=200000) -> Set[str]:
    subs = set()
    p = Path(wordlist_path)
    if not p.exists(): return subs
    with p.open("r", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if i >= max_entries: break
            w = line.strip()
            if not w or w.startswith("#"): continue
            subs.add(f"{w}.{domain}")
    return subs

# ---------------- RESOLUTION ----------------
def resolve_name(name: str, resolver=None, timeout=5) -> List[str]:
    ips = set()
    try:
        r = resolver or dns.resolver.Resolver()
        r.lifetime = timeout
        try:
            ans = r.resolve(name, "A", lifetime=timeout)
            ips |= {rr.to_text() for rr in ans}
        except: pass
        try:
            ans = r.resolve(name, "AAAA", lifetime=timeout)
            ips |= {rr.to_text() for rr in ans}
        except: pass
    except: pass
    return list(ips)

# ---------------- LIVENESS CHECK ----------------
async def http_check(session: aiohttp.ClientSession, url: str, timeout=6) -> bool:
    try:
        async with session.head(url, timeout=timeout, allow_redirects=True) as r:
            return r.status < 400
    except:
        try:
            async with session.get(url, timeout=timeout, allow_redirects=True) as r2:
                return r2.status < 400
        except: return False

async def tcp_port_open(ip: str, port: int, timeout=3) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return True
    except: return False

async def is_live(subdomain: str, resolved_ips: List[str], session: aiohttp.ClientSession, timeout=6) -> Tuple[bool, str]:
    schemes = ["https://", "http://"]
    for s in schemes:
        if await http_check(session, s + subdomain, timeout=timeout):
            return True, s
    common_ports = [443, 80]
    for ip in resolved_ips:
        for p in common_ports:
            if await tcp_port_open(ip, p, timeout=3):
                return True, f"tcp:{ip}:{p}"
    return False, ""

# ---------------- SHODAN ----------------
def shodan_query(api_key: str, ip: str) -> Dict:
    if not api_key: return {}
    try:
        sh = shodan.Shodan(api_key)
        info = sh.host(ip)
        ports = info.get("ports", [])
        vulns = info.get("vulns") or info.get("vulnerability") or []
        return {"ports": ports, "vulns": vulns, "raw": info}
    except Exception as e:
        return {"error": str(e)}

# ---------------- MAIN PIPELINE ----------------
async def run_pipeline(domain, wordlist, vt_key, st_key, shodan_key, threads=50, timeout=6, out_file=None):
    start = time.time()
    candidates = set()

    if wordlist:
        print(GREEN + "[*] Running brute-force wordlist..." + RESET)
        bf = brute_force_from_wordlist(domain, wordlist)
        print(GREEN + f"[+] Bruteforce produced {len(bf)} candidates" + RESET)
        candidates |= bf

    async with aiohttp.ClientSession() as session:
        api_tasks = []
        if vt_key: api_tasks.append(vt_subdomains(session, domain, vt_key))
        if st_key: api_tasks.append(st_subdomains(session, domain, st_key))
        if api_tasks:
            print(GREEN + "[*] Querying APIs..." + RESET)
            results = await asyncio.gather(*api_tasks)
            for r in results: candidates |= r
            print(GREEN + f"[+] Total candidates after APIs: {len(candidates)}" + RESET)

        candidates = {c.lower().strip() for c in candidates if c and c.endswith(domain)}
        candidate_list = list(candidates)

        print(GREEN + "[*] Resolving candidate names (A/AAAA)..." + RESET)
        resolver = dns.resolver.Resolver()
        loop = asyncio.get_running_loop()
        resolved_map = {}
        with ThreadPoolExecutor(max_workers=threads) as pool:
            tasks = [loop.run_in_executor(pool, resolve_name, name, resolver, timeout) for name in candidate_list]
            reslist = await asyncio.gather(*tasks)
        for name, ips in zip(candidate_list, reslist):
            if ips: resolved_map[name] = ips
        print(GREEN + f"[+] Resolved {len(resolved_map)} names to IP(s)" + RESET)

        print(GREEN + "[*] Checking if resolved names are live (http/tcp)..." + RESET)
        live_map = {}
        sem = asyncio.Semaphore(200)
        async def check_one(sub, ips):
            async with sem:
                ok, how = await is_live(sub, ips, session, timeout)
                return sub, ok, how
        results = await asyncio.gather(*[check_one(s, ips) for s, ips in resolved_map.items()])
        for sub, ok, how in results:
            if ok: live_map[sub] = {"ips": resolved_map.get(sub, []), "how": how}
        print(GREEN + f"[+] {len(live_map)} live subdomains" + RESET)

        aggregated = {}
        public_ips = set()
        for sub, info in live_map.items():
            ips = info["ips"]
            priv = [ip for ip in ips if is_private_ip(ip)]
            pub = [ip for ip in ips if not is_private_ip(ip)]
            for ip in pub: public_ips.add(ip)
            aggregated[sub] = {"ips": ips, "private": priv, "public": pub, "how": info["how"]}

        shodan_results = {}
        if shodan_key and public_ips:
            print(GREEN + "[*] Querying Shodan for public IPs..." + RESET)
            with ThreadPoolExecutor(max_workers=10) as pool:
                futs = [loop.run_in_executor(pool, shodan_query, shodan_key, ip) for ip in public_ips]
                sh_res = await asyncio.gather(*futs)
            for ip, r in zip(list(public_ips), sh_res):
                shodan_results[ip] = r

        report = {"domain": domain, "timestamp": int(time.time()), "subdomains": aggregated, "shodan": shodan_results}
        if out_file:
            with open(out_file, "w") as fh: json.dump(report, fh, indent=2)
            print(GREEN + f"[+] Wrote report to {out_file}" + RESET)
        else:
            print(json.dumps(report, indent=2))

    print(GREEN + f"[+] Done in {time.time()-start:.1f}s" + RESET)

# ---------------- CUSTOM HELP ----------------
def print_help():
    print(YELLOW + "Usage:" + RESET)
    print(f"  python subenum.py -d <domain> [-w <wordlist>] [--vt-key KEY] [--st-key KEY] [--shodan-key KEY]")
    print(YELLOW + "\nOptions:" + RESET)
    print(f"  -d, --domain         {GREEN}Target domain (e.g. example.com){RESET}")
    print(f"  -w, --wordlist       {GREEN}Path to wordlist for bruteforce (optional){RESET}")
    print(f"  --vt-key             {GREEN}VirusTotal API key (optional){RESET}")
    print(f"  --st-key             {GREEN}SecurityTrails API key (optional){RESET}")
    print(f"  --shodan-key         {GREEN}Shodan API key (optional){RESET}")
    print(f"  --threads            {GREEN}Resolver threadpool size (default 50){RESET}")
    print(f"  --timeout            {GREEN}Network timeout in seconds (default 6){RESET}")
    print(f"  -o, --out            {GREEN}Write JSON output to file{RESET}")
    print(f"  --team               {GREEN}Team name for banner display{RESET}")
    print(f"  --font               {GREEN}Pyfiglet font for banner (default slant){RESET}")
    print(f"  --no-color           {GREEN}Disable colored banner output{RESET}")
    print(YELLOW + "\nExample:" + RESET)
    print(f"  python subenum.py -d example.com -w wordlist.txt --vt-key YOURKEY --st-key YOURKEY\n")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    print_banner("Cyber Hunters")

    # Check if no arguments were passed or help is requested
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-w", "--wordlist", default=None)
    parser.add_argument("--vt-key", default=None)
    parser.add_argument("--st-key", default=None)
    parser.add_argument("--shodan-key", default=None)
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--timeout", type=int, default=6)
    parser.add_argument("-o", "--out", default=None)
    parser.add_argument("--team", default="Cyber Hunters")
    parser.add_argument("--font", default="slant")
    parser.add_argument("--no-color", action="store_true")

    args = parser.parse_args()

    # If user did not provide required domain, show menu instead of argparse error
    if not args.domain:
        print_help()
        sys.exit(0)

    vt = args.vt_key or VT_API
    st = args.st_key or ST_API
    sh = args.shodan_key or SHODAN_API

    try:
        asyncio.run(run_pipeline(args.domain, args.wordlist, vt, st, sh, args.threads, args.timeout, args.out))
    except KeyboardInterrupt:
        print(RED + "Interrupted by user" + RESET)
        sys.exit(1)
