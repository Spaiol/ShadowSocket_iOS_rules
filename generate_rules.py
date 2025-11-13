import requests
import json
from pathlib import Path

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)
sources = json.load(open("sources.json", encoding="utf-8"))

def fetch_json(url):
    print(f"🔹 Fetching {url}")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()

def parse_domains(data):
    domains, ips = set(), set()
    for rule in data.get("rules", []):
        for key in ("domain_suffix", "domain_keyword", "domain"):
            for d in rule.get(key, []):
                domains.add(d.strip().lower())
        for key in ("ip_cidr", "ip_cidr6"):
            for ip in rule.get(key, []):
                ips.add(ip.strip())
    return domains, ips

def make_shadowrocket_rule(domains, ips, policy):
    rules = []
    for d in sorted(domains):
        rules.append(f"DOMAIN-SUFFIX,{d},{policy}")
    for ip in sorted(ips):
        rules.append(f"IP-CIDR,{ip},{policy},no-resolve")
    return rules

def main():
    proxy_domains, proxy_ips = set(), set()
    direct_domains, direct_ips = set(), set()

    # 处理黑名单
    for url in sources["blacklist"]:
        data = fetch_json(url)
        d, i = parse_domains(data)
        proxy_domains |= d
        proxy_ips |= i

    # 处理白名单
    for url in sources["whitelist"]:
        data = fetch_json(url)
        d, i = parse_domains(data)
        direct_domains |= d
        direct_ips |= i

    # 生成规则文件
    proxy_rules = make_shadowrocket_rule(proxy_domains, proxy_ips, "Proxy")
    direct_rules = make_shadowrocket_rule(direct_domains, direct_ips, "DIRECT")

    (OUTPUT_DIR / "proxy.list").write_text("\n".join(proxy_rules), encoding="utf-8")
    (OUTPUT_DIR / "direct.list").write_text("\n".join(direct_rules), encoding="utf-8")

    print(f"✅ Generated {len(proxy_rules)} proxy rules and {len(direct_rules)} direct rules.")

if __name__ == "__main__":
    main()
