import requests
import json
import yaml
from pathlib import Path

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)
sources = json.load(open("sources.json", encoding="utf-8"))


# ----------------------------------------
# 下载文件
# ----------------------------------------
def fetch_text(url):
    print(f"🔹 Fetching {url}")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


# ----------------------------------------
# 解析 MetaCubeX geosite / geoip JSON
# ----------------------------------------
def parse_geosite_json(data):
    domains, ips = set(), set()

    for rule in data.get("rules", []):
        # 域名类
        for key in ("domain_suffix", "domain", "domain_keyword"):
            for d in rule.get(key, []):
                domains.add(d.strip().lower())

        # IP 类
        for key in ("ip_cidr", "ip_cidr6"):
            for ip in rule.get(key, []):
                ips.add(ip.strip())

    return domains, ips


# ----------------------------------------
# 解析 Clash YAML（如 AppleAI）
# payload:
#   - DOMAIN-SUFFIX,xxx
#   - IP-CIDR,xxx
# ----------------------------------------
def parse_clash_yaml(text):
    data = yaml.safe_load(text)
    domains, ips = set(), set()

    for item in data.get("payload", []):
        parts = item.split(",")
        if len(parts) < 2:
            continue

        rule_type = parts[0].strip().upper()
        value = parts[1].strip()

        if rule_type in ("DOMAIN", "DOMAIN-SUFFIX"):
            domains.add(value)

        elif rule_type == "DOMAIN-KEYWORD":
            # Shadowrocket 支持 DOMAIN-KEYWORD
            domains.add(f"*{value}*")

        elif rule_type in ("IP-CIDR", "IP-CIDR6"):
            ips.add(value)

    return domains, ips


# ----------------------------------------
# 自动识别文件格式并解析
# ----------------------------------------
def parse_any(url):
    text = fetch_text(url)

    if url.endswith(".json"):
        data = json.loads(text)
        return parse_geosite_json(data)

    if url.endswith(".yaml") or url.endswith(".yml"):
        return parse_clash_yaml(text)

    raise ValueError(f"❌ Unsupported format: {url}")


# ----------------------------------------
# 生成 Shadowrocket 规则
# ----------------------------------------
def make_shadowrocket_rules(domains, ips, policy):
    rules = []

    for d in sorted(domains):
        if d.startswith("*") and d.endswith("*"):
            rules.append(f"DOMAIN-KEYWORD,{d[1:-1]},{policy}")
        else:
            rules.append(f"DOMAIN-SUFFIX,{d},{policy}")

    for ip in sorted
