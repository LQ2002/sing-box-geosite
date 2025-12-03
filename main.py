import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
from io import StringIO

# 映射字典
MAP_DICT = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 
            'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
            'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"}

def read_yaml_from_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        yaml_data = yaml.safe_load(response.text)
        return yaml_data
    except Exception as e:
        print(f"读取YAML失败: {url}, 错误: {str(e)}")
        return None

def parse_domain_list_format(content):
    """
    解析纯域名列表格式的内容
    纯域名列表格式: 每行一个域名
    例如: example.com
         *.ads.example.com
    """
    rows = []
    lines = content.strip().splitlines()
    
    for line in lines:
        line = line.strip()
        
        # 跳过空行和注释行
        if not line or line.startswith('#'):
            continue
        
        # 分割行内容（处理可能的行内注释）
        parts = line.split()
        
        if len(parts) < 1:
            continue
        
        domain = parts[0].split('#')[0].strip()
        
        if not domain:
            continue
        
        # 处理通配符域名
        if domain.startswith('*.'):
            # 通配符域名转换为domain_suffix
            domain = domain[2:]  # 移除 *.
            rows.append({
                'pattern': 'DOMAIN-SUFFIX',
                'address': domain,
                'other': None
            })
        elif '*' in domain:
            # 包含通配符但不是标准的*.格式，作为关键字处理
            domain = domain.replace('*', '')
            rows.append({
                'pattern': 'DOMAIN-KEYWORD',
                'address': domain,
                'other': None
            })
        else:
            # 普通域名
            rows.append({
                'pattern': 'DOMAIN',
                'address': domain,
                'other': None
            })
    
    if rows:
        return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
    else:
        return pd.DataFrame(columns=['pattern', 'address', 'other'])
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
                # 清理域名（移除可能的注释）
                domain = domain.split('#')[0].strip()
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

def is_domain_list_format(content):
    """
    判断内容是否为纯域名列表格式
    纯域名列表格式的特征：
    1. 每行只有一个域名（可能带有通配符）
    2. 不包含逗号、等号等特殊格式
    """
    lines = content.strip().splitlines()
    
    # 至少检查前10行非注释行
    valid_domain_lines = 0
    checked_lines = 0
    
    for line in lines:
        line = line.strip()
        
        # 跳过空行和注释
        if not line or line.startswith('#'):
            continue
        
        checked_lines += 1
        if checked_lines > 10:
            break
        
        # 检查是否只有一个单词（域名），且不包含特殊格式字符
        parts = line.split()
        if len(parts) == 1 and ',' not in line and '=' not in line:
            # 检查是否看起来像域名或通配符域名
            domain = parts[0]
            if '.' in domain or '*' in domain:
                valid_domain_lines += 1
    
    # 如果至少有5行符合纯域名格式，就认为是纯域名列表
    return valid_domain_lines >= 5

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

def read_list_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            try:
                # 首先检查是否是hosts格式
                if is_hosts_format(response.text):
                    print(f"检测到hosts格式: {url}")
                    df = parse_hosts_format(response.text)
                    return df, []
                
                # 原有的CSV解析逻辑
                csv_data = StringIO(response.text)
                df = pd.read_csv(csv_data, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'], on_bad_lines='skip')
                
                filtered_rows = []
                rules = []
                # 处理逻辑规则
                if 'AND' in df['pattern'].values:
                    and_rows = df[df['pattern'].str.contains('AND', na=False)]
                    for _, row in and_rows.iterrows():
                        rule = {
                            "type": "logical",
                            "mode": "and",
                            "rules": []
                        }
                        pattern = ",".join(row.values.astype(str))
                        components = re.findall(r'\((.*?)\)', pattern)
                        for component in components:
                            for keyword in MAP_DICT.keys():
                                if keyword in component:
                                    match = re.search(f'{keyword},(.*)', component)
                                    if match:
                                        value = match.group(1)
                                        rule["rules"].append({
                                            MAP_DICT[keyword]: value
                                        })
                        rules.append(rule)
                for index, row in df.iterrows():
                    if 'AND' not in row['pattern']:
                        filtered_rows.append(row)
                df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
                return df_filtered, rules
            except Exception as e:
                print(f"解析URL内容失败: {url}, 错误: {str(e)}")
                # 返回空DataFrame和空规则列表，而不是None
                return pd.DataFrame(columns=['pattern', 'address', 'other', 'other2', 'other3']), []
        else:
            print(f"请求URL失败: {url}, 状态码: {response.status_code}")
            # 返回空DataFrame和空规则列表，而不是None
            return pd.DataFrame(columns=['pattern', 'address', 'other', 'other2', 'other3']), []
    except Exception as e:
        print(f"请求URL出错: {url}, 错误: {str(e)}")
        return pd.DataFrame(columns=['pattern', 'address', 'other', 'other2', 'other3']), []

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    try:
        rules = []
        # 根据链接扩展名分情况处理
        if link.endswith('.yaml') or link.endswith('.txt'):
            try:
                yaml_data = read_yaml_from_url(link)
                rows = []
                if yaml_data is None:
                    return pd.DataFrame(columns=['pattern', 'address', 'other']), []
                
                if not isinstance(yaml_data, str):
                    items = yaml_data.get('payload', [])
                    if not items:
                        items = []
                else:
                    lines = yaml_data.splitlines()
                    if lines:
                        line_content = lines[0]
                        items = line_content.split()
                    else:
                        items = []
                
                for item in items:
                    address = item.strip("'")
                    if ',' not in item:
                        if is_ipv4_or_ipv6(item):
                            pattern = 'IP-CIDR'
                        else:
                            if address.startswith('+') or address.startswith('.'):
                                pattern = 'DOMAIN-SUFFIX'
                                address = address[1:]
                                if address.startswith('.'):
                                    address = address[1:]
                            else:
                                pattern = 'DOMAIN'
                    else:
                        parts = item.split(',', 1)
                        if len(parts) == 2:
                            pattern, address = parts
                        else:
                            pattern = 'DOMAIN'
                            address = parts[0]
                    
                    if ',' in address:
                        address = address.split(',', 1)[0]
                    
                    rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
                
                if rows:
                    df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
                else:
                    df = pd.DataFrame(columns=['pattern', 'address', 'other'])
            except Exception as e:
                print(f"解析YAML/TXT失败: {link}, 错误: {str(e)}")
                df, rules = read_list_from_url(link)
        else:
            # 对于没有扩展名或其他扩展名的文件，直接调用read_list_from_url
            # 该函数会自动检测是否为hosts格式
            df, rules = read_list_from_url(link)
        
        # 确保df不为None
        if df is None:
            df = pd.DataFrame(columns=['pattern', 'address', 'other'])
        
        return df, rules
    except Exception as e:
        print(f"处理链接失败: {link}, 错误: {str(e)}")
        # 返回空DataFrame和空规则列表
        return pd.DataFrame(columns=['pattern', 'address', 'other']), []

# 对字典进行排序，含list of dict
def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0] if d else "")
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory, custom_names=None, custom_entries=None):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(parse_and_convert_to_dataframe, [link]))
            
            # 检查结果是否有效
            if not results or len(results) == 0:
                print(f"未能获取数据: {link}")
                return None
                
            dfs = [df for df, rules in results if df is not None]
            rules_list = [rules for df, rules in results if rules is not None]
            
            # 检查是否有有效的DataFrame
            if not dfs:
                print(f"未获取到有效数据: {link}")
                return None
                
            try:
                df = pd.concat(dfs, ignore_index=True)
            except Exception as e:
                print(f"合并DataFrame失败: {link}, 错误: {str(e)}")
                df = pd.DataFrame(columns=['pattern', 'address', 'other'])
                
        # 确保df有必要的列
        if 'pattern' not in df.columns:
            print(f"DataFrame缺少pattern列: {link}")
            return None
            
        # 删除pattern中包含#号的行
        df = df[~df['pattern'].str.contains('#', na=False)].reset_index(drop=True)
        
        # 删除不在字典中的pattern
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        
        # 如果DataFrame为空，返回None
        if df.empty:
            print(f"过滤后DataFrame为空: {link}")
            return None
        
        df = df.drop_duplicates().reset_index(drop=True)  # 删除重复行
        df['pattern'] = df['pattern'].replace(MAP_DICT)  # 替换pattern为字典中的值
        os.makedirs(output_directory, exist_ok=True)  # 创建自定义文件夹

        result_rules = {"version": 2, "rules": []}
        domain_entries = []
        domain_suffix_entries = []
        ip_cidr_entries = []
        domain_keyword_entries = []
        domain_regex_entries = []
        geoip_entries = []
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
                ip_cidr_entries.extend([address.strip() for address in addresses])
            elif pattern == 'domain_keyword':
                domain_keyword_entries.extend([address.strip() for address in addresses])
            elif pattern == 'domain_regex':
                domain_regex_entries.extend([address.strip() for address in addresses])
            elif pattern == 'geoip':
                geoip_entries.extend([address.strip() for address in addresses])
            elif pattern == 'port':
                port_entries.extend([address.strip() for address in addresses])
            elif pattern == 'source_port':
                source_port_entries.extend([address.strip() for address in addresses])
            elif pattern == 'source_ip_cidr':
                source_ip_cidr_entries.extend([address.strip() for address in addresses])
                
        # 获取规则名称
        if custom_names and link in custom_names:
            rule_name = custom_names[link]
        else:
            rule_name = os.path.basename(link).split('.')[0]
            
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
                    domain_keyword_entries.append(entry_value)
        
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
            
        if geoip_entries:
            geoip_entries = list(set(geoip_entries))
            result_rules["rules"].append({'geoip': geoip_entries})
            
        if port_entries:
            port_entries = list(set(port_entries))
            result_rules["rules"].append({'port': port_entries})
            
        if source_port_entries:
            source_port_entries = list(set(source_port_entries))
            result_rules["rules"].append({'source_port': source_port_entries})
            
        if source_ip_cidr_entries:
            source_ip_cidr_entries = list(set(source_ip_cidr_entries))
            result_rules["rules"].append({'source_ip_cidr': source_ip_cidr_entries})
        
        # 使用自定义名称或原始文件名
        file_name = os.path.join(output_directory, f"{rule_name}.json")
        
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        return file_name
    except Exception as e:
        print(f'获取链接出错，已跳过：{link}，原因：{str(e)}')
        return None

def determine_entry_type(entry):
    """根据条目内容确定其类型"""
    entry = entry.strip()
    
    # 检查是否是IP或CIDR
    if is_ipv4_or_ipv6(entry):
        return 'ip_cidr', entry
    
    # 如果以点开头，是域名后缀
    if entry.startswith('.'):
        return 'domain_suffix', entry[1:]
    
    # 如果包含通配符或关键词指示符，是域名关键字
    if '*' in entry or entry.startswith('+'):
        cleaned_entry = entry.replace('*', '').replace('+', '')
        return 'domain_keyword', cleaned_entry
    
    # 默认为域名
    return 'domain', entry

def read_links_file():
    """读取links.txt文件，返回链接和自定义名称的映射"""
    links = []
    custom_names = {}
    
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
        return [], {}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as links_file:
            link_lines = links_file.read().splitlines()
            
        print(f"成功读取文件: {file_path}")
        
        for line in link_lines:
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    url, custom_name = parts
                    links.append(url)
                    custom_names[url] = custom_name
                else:
                    links.append(line)
                    
        return links, custom_names
    except Exception as e:
        print(f"读取links.txt文件失败: {str(e)}")
        return [], {}

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
        with open(file_path, 'r', encoding='utf-8') as config_file:
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
    links, custom_names = read_links_file()
    
    if not links:
        print("未能读取到有效的链接，请检查links.txt文件")
        return
        
    # 读取Custom.config
    custom_entries = read_custom_config()
    
    # 确保输出目录存在
    output_dir = "./"
    os.makedirs(output_dir, exist_ok=True)
    result_file_names = []
    
    for link in links:
        result_file_name = parse_list_file(
            link, 
            output_directory=output_dir, 
            custom_names=custom_names,
            custom_entries=custom_entries
        )
        
        if result_file_name:
            result_file_names.append(result_file_name)
            print(f"成功处理: {link} -> {result_file_name}")
        else:
            print(f"处理失败: {link}")
    
    # 打印生成的文件名总数
    print(f"成功生成 {len(result_file_names)} 个文件")

if __name__ == "__main__":
    main()
