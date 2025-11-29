#!/usr/bin/env python3
"""
extractJs_final.py — Powerful JS Extractor & Downloader
Extracts JavaScript file URLs from response using multiple regex patterns,
"""

import argparse
import html
import os
import re
import sys
import random
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

requests.packages.urllib3.disable_warnings()

MAX_WORKERS = 10
SKIP_SCHEMES = ("javascript:", "data:", "mailto:", "tel:", "#")
UA_FILE = Path("/home/bugdotexe/bbrecon/tools/wordlist/user-agents.txt")

DOMAIN_START_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.[a-zA-Z]{2,}\/', re.I)

PATTERNS = [
    re.compile(r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\bimport\s*\(\s*["\']([^"\']+)["\']\s*\)', re.I),
    re.compile(r'\bimport\s+["\']([^"\']+)["\']', re.I),
    re.compile(r'\bfetch\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\baxios\.\w+\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'xhr\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I),
]

DOMAIN_TOKEN_RE = re.compile(r'([a-z0-9\-]+\.)+[a-z]{2,}', re.I)

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

def log_info(msg): print(f"{Colors.BLUE}[INFO]{Colors.ENDC} {msg}")
def log_success(msg): print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} {msg}")
def log_warn(msg): print(f"{Colors.YELLOW}[WARN]{Colors.ENDC} {msg}")
def log_err(msg): print(f"{Colors.RED}[ERROR]{Colors.ENDC} {msg}")

def get_session_spoofed():
    session = requests.Session()
    ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    if UA_FILE.exists():
        try:
            lines = UA_FILE.read_text().splitlines()
            if lines: ua = random.choice(lines)
        except: pass

    headers = { "User-Agent": ua, "X-Forwarded-For": ip, "Client-IP": ip, "X-Real-IP": ip }
    session.headers.update(headers)
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def generate_full_filename(url):
    try:
        parsed = urlparse(url)
        clean_domain = parsed.netloc.replace('.', '-')
        clean_path = parsed.path.lstrip('/').replace('/', '_')
        if not clean_path: clean_path = "index.js"
        final_name = f"{clean_domain}_{clean_path}".split('?')[0]

        if len(final_name) > 240:
            path_hash = hashlib.md5(parsed.path.encode()).hexdigest()[:10]
            ext = os.path.splitext(final_name)[1]
            final_name = f"{clean_domain}_{path_hash}{ext}"
        return final_name
    except:
        return hashlib.md5(url.encode()).hexdigest() + ".js"

def normalize_url(base: str, candidate: str) -> str:
    c = html.unescape(candidate.strip())
    if any(char in c for char in ['{', '}', ';', '\n', ' ', '<', '>']):
        return ""
    if not c or any(c.lower().startswith(s) for s in SKIP_SCHEMES):
        return ""

    c = c.strip(",;\"'")
    c = c.replace("\\/", "/")
    
    try:
        full = ""
        if c.startswith("//"):
            full = "https:" + c
            
        elif c.startswith(("http://", "https://")):
            full = c

        elif not c.startswith('/') and DOMAIN_START_RE.match(c):
             full = "https://" + c

        else:
            full = urljoin(base, c)
            
        if not full.startswith(("http://", "https://")):
            return ""
            
        return full
    except Exception:
        return ""

def infer_domain_from_path(p: Path) -> str:
    m = DOMAIN_TOKEN_RE.search(str(p))
    if m: return m.group(0)
    return "localhost"

def extract_candidates(text: str):
    for rx in PATTERNS:
        for m in rx.findall(text):
            yield m.strip()

def read_text_safe(path: Path, max_size=5 * 1024 * 1024) -> str:
    try:
        if path.stat().st_size > max_size: return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception: return ""

def process_file(path: Path):
    text = read_text_safe(path)
    if not text: return set()
    domain = infer_domain_from_path(path)
    base = f"https://{domain}/"
    results = set()
    for cand in extract_candidates(text):
        full = normalize_url(base, cand)
        if full: results.add(full)
    return results

def gather_files(single: Path = None, directory: Path = None):
    files = []
    if single and single.is_file(): files.append(single)
    if directory:
        for p in directory.rglob("*"):
            if p.is_file() and os.access(p, os.R_OK): files.append(p)
    return files

def extract_main(args):
    files = gather_files(args.file, args.dir)
    if not files:
        log_err("No readable files found.")
        return 1
    log_info(f"Scanning {len(files)} file(s)...")
    results = set()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = {ex.submit(process_file, f): f for f in files}
        for fut in as_completed(futures):
            res = fut.result()
            if res: results.update(res)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for u in sorted(results):
            fh.write(u + "\n")
    log_success(f"Found {len(results)} VALID JS URLs → {args.output}")
    return 0

def download_js_files(url_file: Path, out_dir: Path, jobs=8):
    out_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Downloading JS files from {url_file} ...")
    raw_lines = url_file.read_text().splitlines()
    urls = [line.strip() for line in raw_lines if line.strip().startswith("http")]
    
    downloaded = set()
    def fetch(u):
        filename = generate_full_filename(u)
        save_path = out_dir / filename
        if save_path.exists(): return None
        session = get_session_spoofed()
        try:
            r = session.get(u, timeout=15, verify=False, stream=True)
            if r.status_code == 200:
                with open(save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                return filename
        except Exception: pass
        return None

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(fetch, u): u for u in urls}
        for fut in as_completed(futs):
            res = fut.result()
            if res: downloaded.add(res)
    log_success(f"Downloaded {len(downloaded)} JS files → {out_dir}")
    return downloaded

def extract_real_sourcemaps(js_url_file: Path, out_file: Path, jobs=8):
    urls = [u.strip() for u in js_url_file.read_text().splitlines() if u.strip()]
    maps = set()
    pattern = re.compile(r'(?://#|//@)\s*sourceMappingURL\s*=\s*(\S+)', re.I)
    def fetch_and_extract(u):
        try:
            r = requests.get(u, timeout=15, verify=False)
            if r.status_code != 200 or not r.text: return None
            found = []
            for m in pattern.findall(r.text):
                m = m.strip().rstrip(";")
                if m.startswith("data:") and "base64," in m:
                    parsed = urlparse(u)
                    if parsed.path.endswith(".map"): synthetic = u
                    elif parsed.path.endswith(".js"): synthetic = u + ".map" if not u.endswith(".js.map") else u
                    else: synthetic = u + ".map"
                    found.append(synthetic)
                    continue
                found.append(urljoin(u, m))
            return found
        except Exception: return None
    log_info(f"Resolving sourcemaps from {len(urls)} JS URLs...")
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(fetch_and_extract, u): u for u in urls}
        for fut in as_completed(futs):
            res = fut.result()
            if res: maps.update(res)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as fh:
        for m in sorted(maps):
            fh.write(m + "\n")
    log_success(f"Extracted {len(maps)} full sourcemap URLs → {out_file}")
    return maps

def main():
    parser = argparse.ArgumentParser(description="Clean JS Extractor & Downloader")
    parser.add_argument("-f", "--file", type=Path, help="Input file")
    parser.add_argument("-d", "--dir", type=Path, help="Input directory")
    parser.add_argument("-o", "--output", type=Path, default=Path("js_urls.txt"), help="Output file")
    parser.add_argument("--download", type=Path, help="Download directory")
    parser.add_argument("--findmaps", action="store_true", help="Find sourcemaps")
    parser.add_argument("-j", "--jobs", type=int, default=MAX_WORKERS, help="Threads")
    args = parser.parse_args()
    if args.file or args.dir: extract_main(args)
    if args.download: download_js_files(args.output, args.download, args.jobs)
    if args.findmaps: extract_real_sourcemaps(args.output, args.output.with_suffix(".sourcemaps.txt"), args.jobs)

if __name__ == "__main__":
    sys.exit(main())
