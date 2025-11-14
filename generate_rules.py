#!/usr/bin/env python3
"""
generate_rules.py

合并多个 JSON / YAML 源（MetaCubeX geosite/geoip + Clash YAML）
输出单一文件 output/rules.conf，格式带注释分区（Proxy / Direct）。
默认策略：direct；黑名单来源规则设为 proxy，白名单来源设为 direct。
支持 Netflix 分组，将 geoip + geosite 合并为单独分区。
"""

import requests
import json
import yaml
import re
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "output"
OUT_DIR.mkdir(exist_ok=True)

SOURCES_FILE = ROOT / "sources.json"
SNAPSHOT_FILE = OUT_DIR / "snapshot.json"
OUT_FILE = OUT_DIR / "rules.conf"

# timeout for requests
REQ_TIMEOUT = 30

# simple domain validation
DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-.]{0,254}$")

def fetch_text(url):
    try:
        print(f"[fetch] {url}")
        r = requests.get(url, timeout=REQ_TIMEOUT, headers={"User-Agent": "rule-generator/1.0"})
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[error] failed to fetch {url}: {e}")
        return None

def normalize_domain(token):
    if not token or not isinstance(token, str):
        return None
    d = token.strip().lower()
    if d.startswith('.'):
        d = d[1:]
    # strip protocol / path
    d = re.sub(r"^https?://", "", d).split('/')[0]
    # remove trailing colon/port
    d = d.split(':')[0]
    if DOMAIN_RE.match(d):
        return d
    return None

def parse_geosite_json_obj(obj):
    domains = set()
    ips = set()
    rules = obj.get("rules") if isinstance(obj, dict) else None
    if not rules and isinstance(obj, dict):
        rules = obj.get("data") or obj.get("list") or obj.get("rules") or []
    if isinstance(rules, dict):
        for k, v in rules.items():
            if isinstance(v, list):
                for x in v:
                    nd = normalize_domain(x)
                    if nd:
                        domains.add(nd)
    elif isinstance(rules, list):
        for item in rules:
            if not isinstance(item, dict):
                continue
            for key in ("domain_suffix", "domain", "domain_keyword", "domain_prefix"):
                arr = item.get(key, []) or []
                if isinstance(arr, str):
                    arr = [arr]
                for token in arr:
                    nd = normalize_domain(token)
                    if nd:
                        if key == "domain_keyword":
                            domains.add(("KEYWORD", token.strip().lower()))
                        else:
                            domains.add(("SUFFIX" if key == "domain_suffix" else "DOMAIN", nd))
            for key in ("ip_cidr", "ip_cidr6"):
                arr = item.get(key, []) or []
                if isinstance(arr, str):
                    arr = [arr]
                for ip in arr:
                    ip = ip.strip()
                    if ip:
                        ips.add(ip)
    return domains, ips

def parse_clash_yaml_text(text):
    domains = set()
    ips = set()
    try:
        obj = yaml.safe_load(text)
    except Exception as e:
        print(f"[error] yaml parse failed: {e}")
        return domains, ips
    if not isinstance(obj, dict):
        return domains, ips
    payload = obj.get("payload") or obj.get("rules") or []
    for item in payload:
        if not isinstance(item, str):
            continue
        parts = [p.strip() for p in item.split(",", 1)]
        if len(parts) < 2:
            continue
        typ = parts[0].upper()
        val = parts[1]
        if typ == "DOMAIN-SUFFIX":
            nd = normalize_domain(val)
            if nd:
                domains.add(("SUFFIX", nd))
        elif typ == "DOMAIN":
            nd = normalize_domain(val)
            if nd:
                domains.add(("DOMAIN", nd))
        elif typ in ("DOMAIN-KEYWORD",):
            kw = val.strip().lower()
            if kw:
                domains.add(("KEYWORD", kw))
        elif typ in ("IP-CIDR", "IP-CIDR6"):
            ips.add(val.strip())
    return domains, ips

def parse_source(url):
    text = fetch_text(url)
    if text is None:
        return set(), set()
    url_lower = url.lower()
    if url_lower.endswith(".json"):
        try:
            obj = json.loads(text)
            return parse_geosite_json_obj(obj)
        except Exception as e:
            print(f"[warn] json parse failed for {url}: {e} -- fallback")
    if url_lower.endswith((".yaml", ".yml")):
        return parse_clash_yaml_text(text)
    try:
        obj = json.loads(text)
        return parse_geosite_json_obj(obj)
    except:
        pass
    try:
        return parse_clash_yaml_text(text)
    except:
        pass
    domains = set()
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[-1]
        nd = normalize_domain(token)
        if nd:
            domains.add(("SUFFIX", nd))
    return domains, ips

def flatten_domain_entries(domain_entries):
    suffixes = set()
    exact = set()
    keywords = set()
    for e in domain_entries:
        if not isinstance(e, tuple):
            continue
        t, val = e
        if t == "SUFFIX":
            suffixes.add(val)
        elif t == "DOMAIN":
            exact.add(val)
        elif t == "KEYWORD":
            keywords.add(val)
    return suffixes, exact, keywords

def compose_lines(suffixes, exacts, keywords, ips, policy):
    lines = []
    for d in sorted(suffixes):
        lines.append(f"DOMAIN-SUFFIX,{d},{policy}")
    for d in sorted(exacts):
        lines.append(f"DOMAIN,{d},{policy}")
    for k in sorted(keywords):
        lines.append(f"DOMAIN-KEYWORD,{k},{policy}")
    for ip in sorted(ips):
        lines.append(f"IP-CIDR,{ip},{policy},no-resolve")
    return lines

def main():
    if not SOURCES_FILE.exists():
        print(f"[fatal] {SOURCES_FILE} not found.")
        return

    sources = json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
    blacklist = sources.get("blacklist", [])
    whitelist = sources.get("whitelist", [])

    proxy_entries = set()
    proxy_ips = set()
    direct_entries = set()
    direct_ips = set()

    # Netflix 分组
    NETFLIX_GROUP = {
        "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/netflix.json",
        "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/netflix.json"
    }
    netflix_entries = set()
    netflix_ips = set()

    snapshot = {"fetched": {}, "errors": []}

    # fetch blacklist
    for url in blacklist:
        try:
            d, i = parse_source(url)
            snapshot["fetched"][url] = {"domains_count": len(d), "ips_count": len(i)}
            if url in NETFLIX_GROUP:
                netflix_entries |= d
                netflix_ips |= i
            else:
                proxy_entries |= d
                proxy_ips |= i
        except Exception as e:
            snapshot["errors"].append({"url": url, "error": str(e)})
            print(f"[error] parsing blacklist {url}: {e}")

    # fetch whitelist
    for url in whitelist:
        try:
            d, i = parse_source(url)
            snapshot["fetched"][url] = {"domains_count": len(d), "ips_count": len(i)}
            direct_entries |= d
            direct_ips |= i
        except Exception as e:
            snapshot["errors"].append({"url": url, "error": str(e)})
            print(f"[error] parsing whitelist {url}: {e}")

    # flatten
    p_suf, p_dom, p_kw = flatten_domain_entries(proxy_entries)
    d_suf, d_dom, d_kw = flatten_domain_entries(direct_entries)
    nf_suf, nf_dom, nf_kw = flatten_domain_entries(netflix_entries)
    nf_ips = netflix_ips

    # 移除与 whitelist 重叠的 proxy
    p_suf -= d_suf
    p_dom -= d_dom
    p_kw -= d_kw
    proxy_ips -= direct_ips

    # compose lines
    proxy_lines = compose_lines(p_suf, p_dom, p_kw, proxy_ips, "proxy")
    direct_lines = compose_lines(d_suf, d_dom, d_kw, direct_ips, "direct")
    netflix_lines = compose_lines(nf_suf, nf_dom, nf_kw, nf_ips, "proxy")

    # build final file content
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    header = [
        "# ========================================",
        "# Auto-generated rules.conf",
        f"# Generated: {ts} (UTC)",
        "# Sources:",
    ]
    for u in blacklist:
        header.append(f"#  - proxy source: {u}")
    for u in whitelist:
        header.append(f"#  - direct source: {u}")
    header.append("# Default policy: direct")
    header.append("# ========================================\n")

    sections = []
    sections.append("# ===== Proxy (blacklist) =====")
    sections.extend(proxy_lines if proxy_lines else ["# (none)"])
    sections.append("\n# ===== Netflix (grouped) =====")
    sections.extend(netflix_lines if netflix_lines else ["# (none)"])
    sections.append("\n# ===== Direct (whitelist) =====")
    sections.extend(direct_lines if direct_lines else ["# (none)"])
    content = "\n".join(header + sections) + "\n"

    # 写文件
    OUT_FILE.write_text(content, encoding="utf-8")
    SNAPSHOT_FILE.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[done] wrote {OUT_FILE} ({len(proxy_lines)} proxy, {len(netflix_lines)} netflix, {len(direct_lines)} direct)")
    print(f"[info] snapshot -> {SNAPSHOT_FILE}")

if __name__ == "__main__":
    main()

# 插入固定头部配置
header_config = """\
ipv6 = true
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, *.local, *.lan, *.internal, e.crashlytics.com, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,fe80::/10,ff00::/8
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
[Rule]
"""

with open(OUT_FILE, "r", encoding="utf-8") as f:
    rules_content = f.read()

with open(OUT_FILE, "w", encoding="utf-8") as f:
    f.write(header_config + "\n" + rules_content)
