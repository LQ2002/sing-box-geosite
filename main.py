import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
import subprocess
from io import StringIO

# 映射字典
MAP_DICT = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 
            'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'DST-PORT': 'port',
            'DEST-PORT': 'port',
            'PROCESS-NAME': 'process_name', 'PROCESS-PATH': 'process_path',
            'NETWORK': 'network',
            'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"}

# ---------------------------------------------------------------------------
# sing-box source format 的 headless rule 字段表
# 依据 https://sing-box.sagernet.org/configuration/rule-set/headless-rule/
# 这些字段绝大多数在本脚本的 (pattern, address) 中间表示里无法表达，
# 所以 sing-box 源格式的规则采用原样直通，不经过 DataFrame。
# ---------------------------------------------------------------------------
SINGBOX_STRING_ARRAY_FIELDS = {
    'network', 'domain', 'domain_suffix', 'domain_keyword', 'domain_regex',
    'source_port_range', 'port_range',
    'process_name', 'process_path', 'process_path_regex',
    'package_name', 'package_name_regex',
    'network_type', 'default_interface_address',
    'wifi_ssid', 'wifi_bssid',
}
SINGBOX_INT_ARRAY_FIELDS = {'port', 'source_port'}
SINGBOX_CIDR_ARRAY_FIELDS = {'ip_cidr', 'source_ip_cidr'}
# query_type 允许数字和字符串混排，例如 ["A", "HTTPS", 32768]
SINGBOX_MIXED_ARRAY_FIELDS = {'query_type'}
SINGBOX_BOOL_FIELDS = {
    'network_is_expensive', 'network_is_constrained', 'network_is_constrainted',
}
SINGBOX_OBJECT_FIELDS = {'network_interface_address'}
SINGBOX_LOGICAL_MAX_DEPTH = 8

# 产出的规则集版本。版本决定客户端的最低要求：
#   1 -> sing-box 1.8   2 -> 1.10   3 -> 1.11   4 -> 1.13   5 -> 1.14
# 见 https://sing-box.sagernet.org/configuration/rule-set/source-format/
RULE_SET_VERSION = 5

def parse_hosts_format(content):
    """
    解析hosts格式的内容
    hosts格式: IP地址 域名 [域名...]
    例如: 0.0.0.0 example.com www.example.com
    """
    rows = []
    lines = content.strip().splitlines()
    
    for line in lines:
        line = line.strip()

        # 跳过空行和注释行
        if not line or line.startswith('#'):
            continue

        # 行内注释整段截掉。逐 token 切 '#' 会把注释里的词
        # （例如 "0.0.0.0 a.com # see docs.example.com"）当成额外域名。
        for sep in ('#', ';'):
            if sep in line:
                line = line.split(sep, 1)[0]
        line = line.strip()
        if not line:
            continue

        # 分割行内容
        parts = line.split()
        
        if len(parts) < 2:
            continue
        
        # 第一部分应该是IP地址
        ip_part = parts[0]
        
        # 验证是否是有效的IP地址
        try:
            ipaddress.ip_address(ip_part)
            # 如果是有效IP，后面的都是域名
            domains = parts[1:]
            
            for domain in domains:
                domain = domain.strip()
                if domain:
                    rows.append({
                        'pattern': 'DOMAIN',
                        'address': domain,
                        'other': None
                    })
        except ValueError:
            # 如果第一部分不是IP地址，跳过这行
            continue
    
    if rows:
        return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
    else:
        return pd.DataFrame(columns=['pattern', 'address', 'other'])

def is_hosts_format(content):
    """
    判断内容是否为hosts格式
    hosts格式的特征：
    1. 行以IP地址开头（0.0.0.0, 127.0.0.1等）
    2. IP地址后跟一个或多个域名
    """
    lines = content.strip().splitlines()
    
    # 至少检查前10行非注释行
    valid_hosts_lines = 0
    checked_lines = 0
    
    for line in lines:
        line = line.strip()
        
        # 跳过空行和注释
        if not line or line.startswith('#'):
            continue
        
        checked_lines += 1
        if checked_lines > 10:
            break
        
        parts = line.split()
        if len(parts) >= 2:
            try:
                # 检查第一部分是否是IP地址
                ipaddress.ip_address(parts[0])
                valid_hosts_lines += 1
            except ValueError:
                pass
    
    # 如果至少有3行符合hosts格式，就认为是hosts文件
    return valid_hosts_lines >= 3


def looks_like_cidr(token):
    """判断 token 是否是带掩码的网段（含 IPv6）。"""
    token = token.strip()
    if '/' not in token:
        return False
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def clean_plain_token(token):
    """清理纯域名/IP列表里的单个 token。"""
    token = token.strip().strip("'\"")
    token = token.rstrip(',')

    # 常见 Adblock 写法的轻量兼容
    if token.startswith('||'):
        token = token[2:]
    if token.startswith('|'):
        token = token[1:]
    if token.endswith('^'):
        token = token[:-1]

    # 去掉可能出现的协议头
    token = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', token)

    # CIDR 要整体保留：'/' 在这里是掩码分隔符而不是 URL 路径分隔符，
    # 按路径切会把 10.0.0.0/8 退化成单地址 10.0.0.0/32。
    if not looks_like_cidr(token):
        token = token.split('/')[0]
        # 只有不含冒号时才按端口切，否则会截断 IPv6
        token = token.split(':')[0] if token.count(':') == 0 else token

    # Clash domainset 的后缀写法 +.example.com
    if token.startswith('+'):
        token = token[1:]
    if token.startswith('.'):
        token = token[1:]
    return token.strip().lower()


def looks_like_domain(token):
    """判断 token 是否像域名。这里故意宽松，兼容规则列表里的真实域名。"""
    token = clean_plain_token(token)
    if not token or ',' in token or '(' in token or ')' in token:
        return False
    if token in MAP_DICT:
        return False
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        pass
    if '.' not in token:
        return False
    if len(token) > 253:
        return False
    labels = token.rstrip('.').split('.')
    if len(labels) < 2:
        return False
    # 首字符允许下划线：_domainkey、_dmarc、_sip 这类都是合法 DNS 标签，
    # 卡死首字符会把 DKIM/SRV 相关的域名整批判否
    label_re = re.compile(r'^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$')
    return all(label_re.match(label) for label in labels)


def is_plain_domain_list(content):
    """
    判断是否为纯域名/IP列表。
    兼容：
    1. 一行一个域名
    2. 一整行用空格分隔很多域名，例如 ShadowWhisperer/RAW/Microsoft
    """
    tokens = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 去掉行内注释，避免把说明文字当 token
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        tokens.extend(line.split())
        if len(tokens) >= 50:
            break

    if not tokens:
        return False

    checked = tokens[:50]
    valid = sum(1 for token in checked if looks_like_domain(token))
    # 只要大多数 token 像域名，就按纯域名列表处理。
    # 下限取 1 而不是 3：只有一两个域名的列表同样合法，
    # 卡 3 会让它们掉进 CSV 分支，pattern 变成域名本身后被整体过滤掉。
    # Clash/Surge 的规则行含逗号，looks_like_domain 会判否，不会误入这里。
    return valid >= 1 and valid / len(checked) >= 0.8


def parse_plain_domain_list(content):
    """解析纯域名/IP列表为 DataFrame。"""
    rows = []
    seen = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        for raw_token in line.split():
            raw = raw_token.strip().strip("'\"").rstrip(',')
            # 前导点（.example.com / +.example.com）是后缀写法，
            # clean_plain_token 会把点去掉，所以要在清理前判断
            is_suffix = raw.startswith('.') or raw.startswith('+.')

            token = clean_plain_token(raw_token)
            if not token or token in seen:
                continue
            if not looks_like_domain(token):
                continue
            seen.add(token)
            if is_ipv4_or_ipv6(token):
                rows.append({'pattern': 'IP-CIDR', 'address': token, 'other': None})
            elif is_suffix:
                rows.append({'pattern': 'DOMAIN-SUFFIX', 'address': token, 'other': None})
            else:
                # 没有前导点就按 DOMAIN 处理，避免把 example.com 误扩大成后缀
                rows.append({'pattern': 'DOMAIN', 'address': token, 'other': None})

    return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])

SURGE_LOGICAL_KEYWORDS = {'AND', 'OR', 'NOT'}


def split_top_level(text):
    """按顶层逗号切分，括号内部的逗号不算分隔符。"""
    parts = []
    depth = 0
    buf = []
    for ch in text:
        if ch == '(':
            depth += 1
            buf.append(ch)
        elif ch == ')':
            depth -= 1
            buf.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    parts.append(''.join(buf).strip())
    return [p for p in parts if p]


def parse_surge_logical_component(component):
    """把 Surge/Clash 的一个复合规则分量转成 sing-box headless rule。"""
    rule, _ = _parse_surge_logical_component(component)
    return rule


def _parse_surge_logical_component(component):
    """返回 (规则或 None, 是否有分量没能完整映射)。

    lossy 必须向上传播：NOT(OR(A, 不支持的条件)) 如果只在内层
    静默丢掉一个分量，外层取反之后会匹配到原本被排除的流量。

    支持嵌套，例如 AND,((OR,((DOMAIN,a.com),(DOMAIN,b.com))),(DEST-PORT,443)),REJECT
    """
    component = component.strip()
    if component.startswith('(') and component.endswith(')'):
        component = component[1:-1].strip()
    if not component:
        return None, True

    head, _, rest = component.partition(',')
    head = head.strip().upper()

    if head in SURGE_LOGICAL_KEYWORDS:
        parts = split_top_level(rest)
        if not parts:
            return None, True
        # parts[0] 是括号包起来的分量组，后面可能还跟着策略名（REJECT/DIRECT/...）
        group = parts[0].strip()
        if group.startswith('(') and group.endswith(')'):
            group = group[1:-1].strip()

        sub_rules = []
        lossy = False
        for part in split_top_level(group):
            parsed, part_lossy = _parse_surge_logical_component(part)
            if parsed is None:
                lossy = True
                continue
            if part_lossy:
                # 子分量自身就是残缺的，例如内层 OR 丢了一个条件
                lossy = True
            sub_rules.append(parsed)

        if not sub_rules:
            return None, True

        # AND / NOT 少一个条件会让规则变宽（匹配到本不该匹配的流量），
        # 这种降级比丢规则更危险，所以整条丢弃。
        # OR 少一个条件只是变窄，保留剩下的是安全的——
        # 但 lossy 要继续往上传，外层若是 AND 或 NOT，收窄会翻转成放宽。
        if lossy and head in ('AND', 'NOT'):
            print(f"  复合规则有分量无法完整映射，整条丢弃: {component[:70]}")
            return None, True

        rule = {
            'type': 'logical',
            'mode': 'or' if head == 'OR' else 'and',
            'rules': sub_rules,
        }
        # sing-box 没有 NOT，用 invert 表达取反
        if head == 'NOT':
            rule['invert'] = True
        return rule, lossy

    # 叶子分量：精确取键，不能用子串匹配。
    # 子串匹配会让 SRC-IP-CIDR,10.0.0.0/8 同时命中 IP-CIDR，多出一条错误规则。
    field = MAP_DICT.get(head)
    if field is None:
        return None, True
    value = clean_rule_value(rest)
    if not value:
        return None, True
    return {field: [value]}, False


def extract_surge_logical_rules(content, stats=None):
    """扫描文本里的 AND / OR / NOT 复合规则。

    必须在进 DataFrame 之前单独扫一遍：这些行字段数不定，
    pd.read_csv 固定 5 列 + on_bad_lines='skip' 会直接把它们丢掉。
    """
    if stats is None:
        stats = {}
    rules = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        if line.split(',', 1)[0].strip().upper() not in SURGE_LOGICAL_KEYWORDS:
            continue
        parsed = parse_surge_logical_component(line)
        if not parsed:
            continue
        cleaned = sanitize_singbox_rule(parsed, stats)
        if cleaned:
            rules.append(cleaned)
    if rules:
        print(f"  解析出 {len(rules)} 条 AND/OR/NOT 复合规则")
    return rules


def is_singbox_rule_set(data):
    """判断对象是否为 sing-box source format 规则集。

    形如 {"version": 4, "rules": [{"domain": [...], "ip_cidr": [...]}]}
    """
    if not isinstance(data, dict):
        return False
    rules = data.get('rules')
    if not isinstance(rules, list) or not rules:
        return False
    return all(isinstance(rule, dict) for rule in rules)


def _as_list(value):
    return value if isinstance(value, list) else [value]


def sanitize_singbox_rule(rule, stats, depth=0):
    """按官方字段表清洗一条 headless rule，返回清洗后的规则或 None。"""
    cleaned, _ = _sanitize_singbox_rule(rule, stats, depth)
    return cleaned


def _sanitize_singbox_rule(rule, stats, depth=0):
    """清洗一条 headless rule，返回 (规则或 None, 是否发生了会放宽匹配的丢弃)。

    来源是远端 URL，不能直接信任：字段表之外的键一律丢弃，
    否则 sing-box 会报 unknown field 让整个规则集编译失败。

    关键在于"丢掉什么会放宽匹配"：
    - 一条 default rule 内的多个字段是 AND 关系，整个字段消失 => 放宽
    - logical and 少一个子规则 => 放宽
    - logical or 少一个子规则 => 收窄，本身安全，但要向上传播：
      外层若是 and 或带 invert，收窄会翻转成放宽
    - 字段内少掉个别取值（某条 CIDR 解析不了）=> 收窄，安全

    放宽是危险的（REJECT 规则会误杀本不该拦的流量），所以一旦发生就整条丢弃。
    """
    if rule.get('type') == 'logical':
        if depth >= SINGBOX_LOGICAL_MAX_DEPTH:
            stats['logical(嵌套过深)'] = stats.get('logical(嵌套过深)', 0) + 1
            return None, True

        mode = str(rule.get('mode', 'and')).lower()
        if mode not in ('and', 'or'):
            mode = 'and'
        inverted = bool(rule.get('invert'))

        sub_rules = []
        lossy = False
        for sub in _as_list(rule.get('rules', [])):
            if not isinstance(sub, dict):
                lossy = True
                continue
            cleaned, sub_lossy = _sanitize_singbox_rule(sub, stats, depth + 1)
            if cleaned is None:
                lossy = True
                continue
            if sub_lossy:
                lossy = True
            sub_rules.append(cleaned)

        if not sub_rules:
            return None, True

        # and 少条件是放宽；or 带 invert 时收窄会翻转成放宽。两者都失败关闭。
        if lossy and (mode == 'and' or inverted):
            stats['logical(子条件缺失,整条丢弃)'] = stats.get('logical(子条件缺失,整条丢弃)', 0) + 1
            return None, True

        out = {'type': 'logical', 'mode': mode, 'rules': sub_rules}
        if inverted:
            out['invert'] = True
        return out, lossy

    out = {}
    dropped_field = False

    for field, value in rule.items():
        if field == 'type':
            continue

        if field == 'invert':
            if value:
                out['invert'] = True
            continue

        if field in SINGBOX_BOOL_FIELDS:
            out[field] = bool(value)
            continue

        if field in SINGBOX_OBJECT_FIELDS:
            if isinstance(value, dict) and value:
                out[field] = value
            else:
                dropped_field = True
            continue

        if field in SINGBOX_INT_ARRAY_FIELDS:
            ports = coerce_ports(_as_list(value), '<sing-box>', field)
            if ports:
                out[field] = ports
            else:
                dropped_field = True
            continue

        if field in SINGBOX_CIDR_ARRAY_FIELDS:
            cidrs = []
            for item in _as_list(value):
                normalized = normalize_ip_cidr(item)
                if normalized:
                    cidrs.append(normalized)
                else:
                    stats[f'{field}(无法解析)'] = stats.get(f'{field}(无法解析)', 0) + 1
            if cidrs:
                out[field] = cidrs
            else:
                dropped_field = True
            continue

        if field in SINGBOX_MIXED_ARRAY_FIELDS:
            items = [v for v in _as_list(value) if isinstance(v, (int, str))]
            if items:
                out[field] = items
            else:
                dropped_field = True
            continue

        if field in SINGBOX_STRING_ARRAY_FIELDS:
            items = [str(v).strip() for v in _as_list(value) if str(v).strip()]
            if items:
                out[field] = items
            else:
                dropped_field = True
            continue

        # 官方字段表之外的键
        stats[field] = stats.get(field, 0) + (len(value) if isinstance(value, list) else 1)
        dropped_field = True

    # 同一条规则内的字段是 AND 关系，少一个字段就等于放宽，整条丢弃
    if dropped_field:
        stats['rule(字段缺失,整条丢弃)'] = stats.get('rule(字段缺失,整条丢弃)', 0) + 1
        return None, True

    if not out:
        return None, True

    return out, False


def parse_singbox_rule_set(data, url=''):
    """把 sing-box source format 的 rules 原样取出（清洗后）。

    刻意不转成 DataFrame：headless rule 有二十多个字段，
    process_name / network_type / port_range / invert / logical 这些
    在 (pattern, address) 的中间表示里根本没有位置，转一圈必然丢信息。
    规则集里的多条 headless rule 本来就是 OR 关系，
    所以直接拼接到最终产物的 rules 数组即可。
    """
    stats = {}
    rules = []
    for rule in data.get('rules', []):
        cleaned = sanitize_singbox_rule(rule, stats)
        if cleaned:
            rules.append(cleaned)

    if stats:
        detail = ', '.join(f"{k}={v}" for k, v in sorted(stats.items()))
        print(f"  sing-box 规则集中已丢弃的字段: {detail}")

    version = data.get('version')
    print(f"  sing-box 源格式: {len(rules)} 条 headless rule (源 version={version})")
    return rules


# DOMAIN-REGEX / URL-REGEX 的值里可以合法地出现逗号，
# 例如 ^ad[0-9]{1,3}\.example\.com$ —— 对这些类型不能按逗号截断
REGEX_PATTERNS = {'URL-REGEX', 'DOMAIN-REGEX'}

# 规则行末尾常见的策略名，解析正则值时用来识别并剥掉尾部策略
KNOWN_POLICIES = {
    'DIRECT', 'REJECT', 'REJECT-DROP', 'REJECT-TINYGIF', 'REJECT-DICT',
    'REJECT-ARRAY', 'REJECT-NO-DROP', 'PROXY', 'no-resolve', 'force-remote-dns',
    'extended-matching', 'pre-matching',
}


def parse_rule_line(line):
    """把一行 Clash/Surge 规则拆成 (pattern, address)。

    手写解析而不是 pd.read_csv：read_csv 固定列数，一旦某行字段数超出
    （复合规则、带策略参数的行），pandas 会把多出来的列当成索引，
    导致其后所有行整体错位——pattern 列拿到的是地址值，随后被整体过滤掉。
    另外 read_csv 会把空值和字符串 "NA" 变成 float nan，
    后续 .strip() 直接抛异常并让整个规则集失败。
    """
    line = line.strip()
    if not line or line.startswith('#') or line.startswith(';'):
        return None

    head, sep, rest = line.partition(',')
    pattern = head.strip()
    if not sep:
        return None

    if pattern.upper() in REGEX_PATTERNS:
        # 正则值整体保留，只在末尾确实是已知策略时剥掉
        value = rest.strip()
        if ',' in value:
            body, _, tail = value.rpartition(',')
            if tail.strip() in KNOWN_POLICIES:
                value = body.strip()
        return pattern, value

    return pattern, clean_rule_value(rest)


def parse_rule_lines(content):
    """按行解析 Clash/Surge 规则文本。"""
    rows = []
    for line in content.splitlines():
        parsed = parse_rule_line(line)
        if not parsed:
            continue
        pattern, address = parsed
        if not pattern or not address:
            continue
        if pattern.upper() in SURGE_LOGICAL_KEYWORDS:
            continue  # 复合规则单独扫，见 extract_surge_logical_rules
        rows.append({'pattern': pattern, 'address': address, 'other': None})
    return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])


def try_parse_clash_payload(content, url=''):
    """识别并解析 Clash 的 payload: 结构。

    按内容判断而不是看 URL 后缀：.yml、带查询串的 .yaml?raw=1
    这类地址同样是合法的 Clash 规则集，靠后缀匹配会把它们
    错当成规则行文本，结果整份规则被过滤光。

    不是这种格式时返回 (None, [])。
    """
    # 必须是独立成行的 payload: 键。只按子串判断的话，
    # 注释里出现过这个词就会触发整份文件的 YAML 解析（几 MB 的列表会很慢）。
    if not re.search(r'^\s*payload\s*:', content, re.M):
        return None, []
    try:
        data = yaml.safe_load(content)
    except Exception as e:
        print(f"payload 解析失败，回退到文本解析: {url}, 错误: {str(e)}")
        return None, []
    if not isinstance(data, dict):
        return None, []
    items = data.get('payload')
    if not isinstance(items, list):
        return None, []

    print(f"检测到 Clash payload 规则集: {url}")
    rows = []
    logical_rules = []
    stats = {}

    for item in items:
        item = str(item).strip().strip("'\"")
        if not item:
            continue

        head = item.split(',', 1)[0].strip().upper()
        if head in SURGE_LOGICAL_KEYWORDS:
            parsed = parse_surge_logical_component(item)
            cleaned = sanitize_singbox_rule(parsed, stats) if parsed else None
            if cleaned:
                logical_rules.append(cleaned)
            continue

        if ',' not in item:
            # 裸域名 / IP / 后缀写法
            if is_ipv4_or_ipv6(item):
                rows.append({'pattern': 'IP-CIDR', 'address': item, 'other': None})
                continue
            address = item
            if address.startswith('+'):
                address = address[1:]
            if address.startswith('.'):
                rows.append({'pattern': 'DOMAIN-SUFFIX', 'address': address[1:], 'other': None})
            else:
                rows.append({'pattern': 'DOMAIN', 'address': address, 'other': None})
            continue

        parsed = parse_rule_line(item)
        if not parsed:
            continue
        pattern, address = parsed
        if pattern and address:
            rows.append({'pattern': pattern, 'address': address, 'other': None})

    if logical_rules:
        print(f"  解析出 {len(logical_rules)} 条 AND/OR/NOT 复合规则")

    return pd.DataFrame(rows, columns=['pattern', 'address', 'other']), logical_rules


def read_list_from_url(url):
    """抓取并解析一个规则源。

    失败时返回 (None, []) —— None 表示"这个源没取到"，
    和"取到了但内容为空"必须区分开，否则多源合并时
    一个源挂掉会被当成空集静默跳过，发布出不完整的规则集。
    """
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"请求URL失败: {url}, 状态码: {response.status_code}")
            return None, []

        try:
            # 最优先：已经是 sing-box source format 就原样直通，不走文本解析
            if response.text.lstrip().startswith('{'):
                try:
                    singbox_data = json.loads(response.text)
                except ValueError:
                    singbox_data = None
                if is_singbox_rule_set(singbox_data):
                    print(f"检测到 sing-box 源格式规则集: {url}")
                    empty = pd.DataFrame(columns=['pattern', 'address', 'other'])
                    return empty, parse_singbox_rule_set(singbox_data, url)

            # Clash 的 payload: 结构按内容识别，不看 URL 后缀
            payload_df, payload_rules = try_parse_clash_payload(response.text, url)
            if payload_df is not None:
                return payload_df, payload_rules

            # hosts 格式
            if is_hosts_format(response.text):
                print(f"检测到hosts格式: {url}")
                return parse_hosts_format(response.text), []

            # 无后缀/纯文本的域名列表：一行一个或空格分隔都可以
            if is_plain_domain_list(response.text):
                print(f"检测到纯域名/IP列表: {url}")
                return parse_plain_domain_list(response.text), []

            # Clash / Surge 规则行
            rules = extract_surge_logical_rules(response.text)
            return parse_rule_lines(response.text), rules
        except Exception as e:
            print(f"解析URL内容失败: {url}, 错误: {str(e)}")
            return None, []
    except Exception as e:
        print(f"请求URL出错: {url}, 错误: {str(e)}")
        return None, []

def is_ipv4_or_ipv6(address):
    """判断字符串是否为 IPv4/IPv6 地址或网段。

    strict=False：允许 10.0.0.1/24 这类主机位未清零的写法。
    用 strict=True 会让它们抛 ValueError 被误判成域名，
    最终以 DOMAIN 的身份混进 domain 列表。
    """
    try:
        ipaddress.IPv4Network(address, strict=False)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address, strict=False)
            return 'ipv6'
        except ValueError:
            return None



def clean_rule_value(value):
    """清理规则值：去掉引号、空白、常见的 Surge 额外参数。"""
    if value is None:
        return ""
    value = str(value).strip().strip('"').strip("'").strip()
    # 只保留第一个字段，避免 no-resolve / force-remote-dns 等参数进入规则值
    if ',' in value:
        value = value.split(',', 1)[0].strip()
    return value


def normalize_ip_cidr(value):
    """把完整 IP / CIDR 规范化成 sing-box 可用的 CIDR 字符串。"""
    value = clean_rule_value(value)
    if not value:
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def ipv4_keyword_prefix_to_cidr(value):
    """
    处理 Surge 专用写法：DOMAIN-KEYWORD,101.226.211.
    这种值在 Surge 中靠字符串包含匹配直接 IP；sing-box domain_keyword 不适合这样用。

    转换规则：
      101.        -> 101.0.0.0/8
      101.226.    -> 101.226.0.0/16
      101.226.211. -> 101.226.211.0/24

    只转换带尾点的 IPv4 前缀，避免把普通关键词误判成网段。
    """
    value = clean_rule_value(value)
    if not value or not value.endswith('.'):
        return None
    if not re.fullmatch(r'(?:\d{1,3}\.){1,3}', value):
        return None

    parts = [p for p in value.split('.') if p != '']
    if not 1 <= len(parts) <= 3:
        return None

    octets = []
    for part in parts:
        try:
            number = int(part)
        except ValueError:
            return None
        if number < 0 or number > 255:
            return None
        octets.append(number)

    prefix_len = len(octets) * 8
    while len(octets) < 4:
        octets.append(0)

    cidr = '.'.join(map(str, octets)) + f'/{prefix_len}'
    try:
        return str(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        return None


def convert_domain_keyword_value(value):
    """
    domain_keyword 的二次分流：
    - IPv4 前缀类关键词：101.226.211. -> ip_cidr 101.226.211.0/24
    - 完整 IP / CIDR：1.1.1.1 或 1.1.1.0/24 -> ip_cidr
    - 其他内容：仍作为 domain_keyword
    """
    value = clean_rule_value(value)
    if not value:
        return None, None

    cidr = ipv4_keyword_prefix_to_cidr(value)
    if cidr:
        return 'ip_cidr', cidr

    cidr = normalize_ip_cidr(value)
    if cidr:
        return 'ip_cidr', cidr

    return 'domain_keyword', value

def parse_and_convert_to_dataframe(link):
    """抓取并解析一个规则源，返回 (df, 复合规则列表)。

    格式一律按内容识别，不看 URL 后缀：靠 .yaml/.txt 后缀路由会让
    .yml、.yaml?raw=1 这类地址走错分支；而 YAML 解析一旦失败
    原先会直接返回空集，没有回退到文本解析。

    df 为 None 表示这个源没取到（网络错误、非 200、解析异常），
    必须和"取到了但内容为空"区分开。
    """
    try:
        return read_list_from_url(link)
    except Exception as e:
        print(f"处理链接失败: {link}, 错误: {str(e)}")
        return None, []


# 对字典进行排序，含list of dict
def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0] if d else "")
    elif isinstance(obj, list):
        items = [sort_dict(x) for x in obj]
        try:
            return sorted(items)
        except TypeError:
            # 混合类型列表无法直接比较，例如 query_type 允许 ["A", 32768]
            return sorted(items, key=lambda v: (type(v).__name__, str(v)))
    else:
        return obj

def parse_list_file(links, rule_name, output_directory, custom_entries=None):
    """把同一个规则名下的所有链接合并成一个规则集文件。

    links 是列表：links.txt 里允许多行共用一个名称，
    这些源必须合并写入，早期实现按单链接覆写会让先处理的源被后者整个盖掉。
    """
    if isinstance(links, str):
        links = [links]
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(parse_and_convert_to_dataframe, links))

            # 检查结果是否有效
            if not results or len(results) == 0:
                print(f"未能获取数据: {rule_name}")
                return None

            # df 为 None 表示这个源根本没取到。多个源合并时只要有一个失败，
            # 就必须让整组失败：否则会拿"部分来源"生成一份不完整的规则集，
            # 覆盖掉 Release 上原本完整的那份，订阅方静默少掉一批规则。
            failed = [link for link, (df, _) in zip(links, results) if df is None]
            if failed:
                for link in failed:
                    print(f"  来源失败: {link}")
                print(f"{rule_name}: {len(failed)}/{len(links)} 个来源失败，整组跳过以免发布不完整规则集")
                return None

            dfs = [df for df, rules in results if not df.empty]

            # sing-box 源格式的规则原样直通，不经过 DataFrame
            passthrough_rules = []
            for _, rules in results:
                if rules:
                    passthrough_rules.extend(rules)

            if not dfs and not passthrough_rules:
                print(f"未获取到有效数据: {rule_name}")
                return None

            if dfs:
                try:
                    df = pd.concat(dfs, ignore_index=True)
                except Exception as e:
                    print(f"合并DataFrame失败: {rule_name}, 错误: {str(e)}")
                    df = pd.DataFrame(columns=['pattern', 'address', 'other'])
            else:
                df = pd.DataFrame(columns=['pattern', 'address', 'other'])
                
        # 确保df有必要的列
        if 'pattern' not in df.columns:
            print(f"DataFrame缺少pattern列: {rule_name}")
            return None
            
        # 删除pattern中包含#号的行
        df = df[~df['pattern'].str.contains('#', na=False)].reset_index(drop=True)
        
        # 统计被丢弃的规则类型再删除，避免源里混入不支持的类型却无声无息
        unsupported = df[~df['pattern'].isin(MAP_DICT.keys())]
        if not unsupported.empty:
            counts = unsupported['pattern'].astype(str).value_counts()
            shown = [f"{p[:30]}={n}" for p, n in list(counts.items())[:8]]
            if len(counts) > 8:
                shown.append(f"...另有 {len(counts) - 8} 种")
            print(f"  {rule_name}: 丢弃 {len(unsupported)} 条不支持的规则类型 "
                  f"({', '.join(shown)})")

        # 删除不在字典中的pattern
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        
        # DataFrame 为空但有直通规则时仍要继续
        if df.empty and not passthrough_rules:
            print(f"过滤后DataFrame为空: {rule_name}")
            return None
        
        df = df.drop_duplicates().reset_index(drop=True)  # 删除重复行
        df['pattern'] = df['pattern'].replace(MAP_DICT)  # 替换pattern为字典中的值
        os.makedirs(output_directory, exist_ok=True)  # 创建自定义文件夹

        result_rules = {"version": RULE_SET_VERSION, "rules": []}
        domain_entries = []
        domain_suffix_entries = []
        ip_cidr_entries = []
        domain_keyword_entries = []
        domain_regex_entries = []
        process_name_entries = []
        process_path_entries = []
        network_entries = []
        # 注意：这里没有 geoip。geoip 是 route rule 的字段，不是 headless rule 的，
        # sing-box 会报 json: unknown field "geoip" 并让整个规则集编译失败。
        # GEOIP 规则现在统一落进"丢弃的规则类型"统计里。
        port_entries = []
        source_port_entries = []
        source_ip_cidr_entries = []
        
        # 处理链接中的内容
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                domain_suffix_entries.extend([address.strip() for address in addresses])
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            elif pattern == 'ip_cidr':
                # 规范化：统一小写、清零主机位，否则同一网段的不同写法去重不掉
                for address in addresses:
                    normalized = normalize_ip_cidr(address)
                    if normalized:
                        ip_cidr_entries.append(normalized)
                    else:
                        print(f"  跳过无法解析的 ip_cidr: {address!r}")
            elif pattern == 'domain_keyword':
                for address in addresses:
                    entry_type, entry_value = convert_domain_keyword_value(address)
                    if entry_type == 'ip_cidr':
                        ip_cidr_entries.append(entry_value)
                    elif entry_type == 'domain_keyword':
                        domain_keyword_entries.append(entry_value)
            elif pattern == 'domain_regex':
                domain_regex_entries.extend([address.strip() for address in addresses])
            elif pattern == 'process_name':
                process_name_entries.extend([address.strip() for address in addresses])
            elif pattern == 'process_path':
                process_path_entries.extend([address.strip() for address in addresses])
            elif pattern == 'network':
                # sing-box 只认 tcp / udp
                for address in addresses:
                    value = address.strip().lower()
                    if value in ('tcp', 'udp'):
                        network_entries.append(value)
                    else:
                        print(f"  {rule_name}: 跳过无法识别的 network: {address!r}")

            elif pattern == 'port':
                # 官方字段表里 port / source_port 是整数数组，写成 "80" 会编译失败
                port_entries.extend(coerce_ports(addresses, rule_name, 'port'))
            elif pattern == 'source_port':
                source_port_entries.extend(coerce_ports(addresses, rule_name, 'source_port'))
            elif pattern == 'source_ip_cidr':
                for address in addresses:
                    normalized = normalize_ip_cidr(address)
                    if normalized:
                        source_ip_cidr_entries.append(normalized)
                    else:
                        print(f"  跳过无法解析的 source_ip_cidr: {address!r}")
                
        # 处理Custom.config中的自定义条目
        if custom_entries and rule_name in custom_entries:
            for entry in custom_entries[rule_name]:
                entry_type, entry_value = determine_entry_type(entry)
                
                if entry_type == 'domain_suffix':
                    domain_suffix_entries.append(entry_value)
                elif entry_type == 'domain':
                    domain_entries.append(entry_value)
                elif entry_type == 'ip_cidr':
                    ip_cidr_entries.append(entry_value)
                elif entry_type == 'domain_keyword':
                    kw_type, kw_value = convert_domain_keyword_value(entry_value)
                    if kw_type == 'ip_cidr':
                        ip_cidr_entries.append(kw_value)
                    elif kw_type == 'domain_keyword':
                        domain_keyword_entries.append(kw_value)
        
        # 添加去重后的条目到规则中
        if domain_entries:
            domain_entries = list(set(domain_entries))
            result_rules["rules"].append({'domain': domain_entries})
            
        if domain_suffix_entries:
            domain_suffix_entries = list(set(domain_suffix_entries))
            result_rules["rules"].append({'domain_suffix': domain_suffix_entries})
            
        if ip_cidr_entries:
            ip_cidr_entries = list(set(ip_cidr_entries))
            result_rules["rules"].append({'ip_cidr': ip_cidr_entries})
            
        if domain_keyword_entries:
            domain_keyword_entries = list(set(domain_keyword_entries))
            result_rules["rules"].append({'domain_keyword': domain_keyword_entries})
            
        if domain_regex_entries:
            domain_regex_entries = list(set(domain_regex_entries))
            result_rules["rules"].append({'domain_regex': domain_regex_entries})

        if process_name_entries:
            result_rules["rules"].append({'process_name': list(set(process_name_entries))})

        if process_path_entries:
            result_rules["rules"].append({'process_path': list(set(process_path_entries))})

        if network_entries:
            result_rules["rules"].append({'network': list(set(network_entries))})
            
        
        if port_entries:
            port_entries = list(set(port_entries))
            result_rules["rules"].append({'port': port_entries})
            
        if source_port_entries:
            source_port_entries = list(set(source_port_entries))
            result_rules["rules"].append({'source_port': source_port_entries})
            
        if source_ip_cidr_entries:
            source_ip_cidr_entries = list(set(source_ip_cidr_entries))
            result_rules["rules"].append({'source_ip_cidr': source_ip_cidr_entries})
        
        # sing-box 源格式的规则原样追加：
        # 规则集里的多条 headless rule 之间是 OR 关系，拼接即合并
        if passthrough_rules:
            seen_rules = {json.dumps(r, sort_keys=True) for r in result_rules["rules"]}
            for rule in passthrough_rules:
                key = json.dumps(rule, sort_keys=True)
                if key not in seen_rules:
                    seen_rules.add(key)
                    result_rules["rules"].append(rule)

        if not result_rules["rules"]:
            print(f"没有可写入的规则: {rule_name}")
            return None

        # 使用自定义名称或原始文件名
        file_name = os.path.join(output_directory, f"{rule_name}.json")
        
        with open(file_name, 'w', encoding='utf-8') as output_file:
            # 不要再对 json.dumps 的结果做反斜杠替换：
            # 它会把 domain_regex 里合法的 \\ 转义压成单个 \，产出非法 JSON
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            output_file.write(result_rules_str)

        srs_path = file_name.replace(".json", ".srs")
        try:
            subprocess.run(["sing-box", "rule-set", "compile", "--output", srs_path, file_name], check=True)
        except FileNotFoundError:
            print("未找到 sing-box，已生成 json，但跳过 srs 编译")
        except subprocess.CalledProcessError as e:
            # 编译失败不能当成功返回：调用方只按返回值计数，
            # CI 又只统计 json，结果会把"这次没生成出来的 srs"
            # 当成陈旧资产从 Release 上删掉，订阅直接 404。
            print(f"sing-box 编译失败: {file_name}, 错误码: {e.returncode}")
            for path in (file_name, srs_path):
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except OSError:
                    pass
            return None
        return file_name
    except Exception as e:
        print(f'生成规则集出错，已跳过：{rule_name}，原因：{str(e)}')
        return None

def coerce_ports(addresses, rule_name, field):
    """端口在 sing-box 规则集里是整数数组，字符串会让 compile 失败。"""
    ports = []
    for address in addresses:
        value = clean_rule_value(address)
        try:
            port = int(value)
        except (TypeError, ValueError):
            print(f"  {rule_name}: 跳过无法解析的 {field}: {address!r}")
            continue
        if 0 <= port <= 65535:
            ports.append(port)
        else:
            print(f"  {rule_name}: 跳过越界的 {field}: {port}")
    return ports


def determine_entry_type(entry):
    """根据 Custom.config 条目内容确定其类型。"""
    entry = clean_rule_value(entry)

    if not entry:
        return 'domain', entry

    # Custom.config 里如果直接写 101.226.211.，也按 Surge IP 前缀处理
    cidr = ipv4_keyword_prefix_to_cidr(entry)
    if cidr:
        return 'ip_cidr', cidr

    # 检查是否是完整 IP 或 CIDR
    cidr = normalize_ip_cidr(entry)
    if cidr:
        return 'ip_cidr', cidr

    # 如果以点开头，是域名后缀
    if entry.startswith('.'):
        return 'domain_suffix', entry[1:]

    # 如果包含通配符或关键词指示符，是域名关键字
    if '*' in entry or entry.startswith('+'):
        cleaned_entry = entry.replace('*', '').replace('+', '').strip()
        kw_type, kw_value = convert_domain_keyword_value(cleaned_entry)
        return kw_type or 'domain_keyword', kw_value or cleaned_entry

    # 默认为域名
    return 'domain', entry

TAG_PLACEHOLDER = '{tag}'

# 标签同时用作输出文件名，必须是安全的文件名片段
TAG_RE = re.compile(r'^[A-Za-z0-9_.@+-]+$')


def expand_tags(url, name):
    """按 sing-box 的多 tag 语义展开一行 links.txt。

    参照 https://sing-box.sagernet.org/configuration/rule-set/
    tag 接受一组标签，用于一次定义多个共享其他选项的规则集；
    url 里的 {tag} 占位符会被替换成每个标签，设置多个标签时必填。

    这里沿用同一套规则：标签既是 {tag} 的替换值，也是各自规则集的名字。

        https://example.com/rule/{tag}.json    360,115,google
        -> 360.json / 115.json / google.json 三个规则集

    返回 [(展开后的链接, 规则名), ...]。
    """
    has_placeholder = TAG_PLACEHOLDER in url
    tags = [t.strip() for t in name.split(',')] if name else []
    tags = [t for t in tags if t]

    if not has_placeholder:
        if len(tags) > 1:
            print(f"跳过：设置了多个标签但 url 里没有 {TAG_PLACEHOLDER} 占位符: {url}")
            return []
        return [(url, name)]

    if not tags:
        print(f"跳过：url 里有 {TAG_PLACEHOLDER} 占位符但没有给出标签: {url}")
        return []

    expanded = []
    seen = set()
    for tag in tags:
        if not TAG_RE.match(tag):
            print(f"跳过非法标签 {tag!r}（只允许字母、数字和 _ . @ + -）: {url}")
            continue
        if tag in seen:
            continue
        seen.add(tag)
        expanded.append((url.replace(TAG_PLACEHOLDER, tag), tag))

    if expanded:
        print(f"{TAG_PLACEHOLDER} 展开出 {len(expanded)} 个规则集: "
              f"{', '.join(t for _, t in expanded)}")
    return expanded


def read_links_file():
    """读取 links.txt，返回 [(链接, 规则名或 None), ...]。

    返回列表而不是 {链接: 规则名} 字典：同一个 URL 完全可以被起
    多个不同的规则名（First / Second），字典会让前面的名字被覆盖，
    最终只生成最后一个。
    """
    entries = []
    
    # 尝试多个可能的路径
    possible_paths = [
        "links.txt",                    # 当前目录
        "../links.txt",                 # 上级目录
        os.path.join(os.getcwd(), "links.txt"),  # 绝对路径
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "links.txt"),  # 脚本所在目录
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "links.txt")  # 脚本所在目录的上级
    ]
    
    file_path = None
    for path in possible_paths:
        if os.path.exists(path):
            file_path = path
            break
    
    if not file_path:
        print(f"找不到links.txt文件，尝试过以下路径: {possible_paths}")
        print(f"当前工作目录: {os.getcwd()}")
        print(f"目录内容: {os.listdir('.')}")
        return []
    
    try:
        # utf-8-sig：Windows 上用记事本/PowerShell 保存会带 BOM，
        # 不剥掉的话第一行的 URL 前面会多一个不可见字符，请求直接失败
        with open(file_path, 'r', encoding='utf-8-sig') as links_file:
            link_lines = links_file.read().splitlines()
            
        print(f"成功读取文件: {file_path}")
        
        for line in link_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            url = parts[0]
            name = parts[1].strip() if len(parts) == 2 else None
            entries.extend(expand_tags(url, name))

        return entries
    except Exception as e:
        print(f"读取links.txt文件失败: {str(e)}")
        return []

def read_custom_config():
    """读取Custom.config文件，返回域名/IP和规则名称的映射"""
    custom_entries = {}
    
    # 尝试多个可能的路径
    possible_paths = [
        "Custom.config",                    # 当前目录
        "../Custom.config",                 # 上级目录
        os.path.join(os.getcwd(), "Custom.config"),  # 绝对路径
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "Custom.config"),  # 脚本所在目录
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Custom.config")  # 脚本所在目录的上级
    ]
    
    file_path = None
    for path in possible_paths:
        if os.path.exists(path):
            file_path = path
            break
    
    if not file_path:
        print(f"找不到Custom.config文件，尝试过以下路径: {possible_paths}")
        print(f"当前工作目录: {os.getcwd()}")
        print(f"目录内容: {os.listdir('.')}")
        return {}
    
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as config_file:
            config_lines = config_file.read().splitlines()
            
        print(f"成功读取文件: {file_path}")
        
        for line in config_lines:
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    domain_or_ip, rule_name = parts
                    
                    if rule_name not in custom_entries:
                        custom_entries[rule_name] = []
                        
                    custom_entries[rule_name].append(domain_or_ip)
                    
        return custom_entries
    except Exception as e:
        print(f"读取Custom.config文件失败: {str(e)}")
        return {}

def main():
    # 显示当前目录结构，帮助调试
    print(f"当前工作目录: {os.getcwd()}")
    print(f"目录内容: {os.listdir('.')}")
    
    # 读取links.txt
    entries = read_links_file()

    if not entries:
        print("未能读取到有效的链接，请检查links.txt文件")
        return
        
    # 读取Custom.config
    custom_entries = read_custom_config()
    
    # 确保输出目录存在
    output_dir = "./"
    os.makedirs(output_dir, exist_ok=True)
    result_file_names = []
    
    # 按规则名分组：links.txt 里同名的多个链接要合并成一个规则集，
    # 逐条处理会让先写的文件被后写的整个覆盖。
    grouped = {}
    for link, name in entries:
        if not name:
            name = os.path.basename(link).split('.')[0]
        # 同一个规则名下重复出现同一个 URL 就没必要抓两次
        if link not in grouped.setdefault(name, []):
            grouped[name].append(link)

    for name, count in ((n, len(ls)) for n, ls in grouped.items() if len(ls) > 1):
        print(f"规则 {name} 由 {count} 个源合并生成")

    failed = []
    for rule_name, group_links in grouped.items():
        result_file_name = parse_list_file(
            group_links,
            rule_name,
            output_directory=output_dir,
            custom_entries=custom_entries
        )

        if result_file_name:
            result_file_names.append(result_file_name)
            print(f"成功处理: {rule_name} ({len(group_links)} 个源) -> {result_file_name}")
        else:
            failed.append(rule_name)
            print(f"处理失败: {rule_name}")

    # 打印生成的文件名总数
    print(f"成功生成 {len(result_file_names)}/{len(grouped)} 个文件")
    if failed:
        print(f"失败的规则: {', '.join(failed)}")

if __name__ == "__main__":
    main()
