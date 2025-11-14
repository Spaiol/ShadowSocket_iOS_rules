#!/usr/bin/env python3
"""
generate_rules.py

合并多个 JSON / YAML 源（MetaCubeX geosite/geoip + Clash YAML）
输出单一文件 output/rules.conf，格式带注释分区（Proxy / Direct）。
默认策略：direct；黑名单来源规则设为 proxy，白名单来源设为 direct。
相同服务的 SITE 和 IP URL 合并为一个分组。
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

REQ_TIMEOUT = 30
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
    d = re.sub(r"^https?://", "", d).split('/')[0]
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
    except:
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
        if typ in ("DOMAIN-SUFFIX",):
            nd = normalize_domain(val)
            if nd:
                domains.add(("SUFFIX", nd))
        elif typ in ("DOMAIN",):
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
        except:
            pass
    if url_lower.endswith(".yaml") or url_lower.endswith(".yml"):
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
    domains, ips = set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        nd = normalize_domain(line.split()[-1])
        if nd:
            domains.add(("SUFFIX", nd))
    return domains, ips

def flatten_domain_entries(entries):
    suffixes, exact, keywords = set(), set(), set()
    for e in entries:
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

    snapshot = {"fetched": {}, "errors": []}

    # 分组存储 proxy/direct 规则
    proxy_groups = {}
    direct_groups = {}

    def group_name_from_url(url):
        """从 URL 中提取服务名作为 group label"""
        name_map = ["netflix", "google", "apple", "youtube", "github", "onedrive", "openai", "microsoft", "telegram", "twitter", "cloudflare", "cloudfront"]
        for n in name_map:
            if n in url.lower():
                return n.capitalize()
        return "Other"

    # 处理 blacklist
    for url in blacklist:
        try:
            d, i = parse_source(url)
            snapshot["fetched"][url] = {"domains_count": len(d), "ips_count": len(i)}
            grp = group_name_from_url(url)
            if grp not in proxy_groups:
                proxy_groups[grp] = {"domains": set(), "ips": set()}
            proxy_groups[grp]["domains"] |= d
            proxy_groups[grp]["ips"] |= i
        except Exception as e:
            snapshot["errors"].append({"url": url, "error": str(e)})

    # 处理 whitelist
    for url in whitelist:
        try:
            d, i = parse_source(url)
            snapshot["fetched"][url] = {"domains_count": len(d), "ips_count": len(i)}
            grp = group_name_from_url(url)
            if grp not in direct_groups:
                direct_groups[grp] = {"domains": set(), "ips": set()}
            direct_groups[grp]["domains"] |= d
            direct_groups[grp]["ips"] |= i
        except Exception as e:
            snapshot["errors"].append({"url": url, "error": str(e)})

    # whitelist override proxy
    for grp in direct_groups:
        if grp in proxy_groups:
            proxy_groups[grp]["domains"] -= direct_groups[grp]["domains"]
            proxy_groups[grp]["ips"] -= direct_groups[grp]["ips"]

    # 生成文件内容
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    header = [
        "# ========================================",
        "# Auto-generated rules.conf",
        f"# Generated: {ts} (UTC)",
        "# Default policy: direct (whitelist) / proxy (blacklist)",
        "# ========================================\n"
    ]

    sections = []

    # Proxy
    sections.append("# ===== Proxy (blacklist) =====")
    for grp, data in proxy_groups.items():
        sections.append(f"\n# ----- {grp} -----")
        suf, dom, kw = flatten_domain_entries(data["domains"])
        lines = compose_lines(suf, dom, kw, data["ips"], "proxy")
        sections.extend(lines if lines else ["# (none)"])

    # Direct
    sections.append("\n# ===== Direct (whitelist) =====")
    for grp, data in direct_groups.items():
        sections.append(f"\n# ----- {grp} -----")
        suf, dom, kw = flatten_domain_entries(data["domains"])
        lines = compose_lines(suf, dom, kw, data["ips"], "direct")
        sections.extend(lines if lines else ["# (none)"])

    # 写入文件
    content = "\n".join(header + sections) + "\n"
    header_config = """\
ipv6 = true
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, *.local, *.lan, *.internal, e.crashlytics.com, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,fe80::/10,ff00::/8
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
[Rule]
"""
    OUT_FILE.write_text(header_config + "\n" + content, encoding="utf-8")
    SNAPSHOT_FILE.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[done] wrote {OUT_FILE}")
    print(f"[info] snapshot -> {SNAPSHOT_FILE}")

if __name__ == "__main__":
    main()
