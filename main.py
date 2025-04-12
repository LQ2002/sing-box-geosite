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

def read_list_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            try:
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

def parse_list_file(link, output_directory, custom_names=None):
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
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
                # domain_entries.extend([address.strip() for address in addresses])  # 1.9以下的版本需要额外处理 domain_suffix
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            else:
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
        # 删除 'domain_entries' 中的重复值
        domain_entries = list(set(domain_entries))
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})

        # 使用自定义名称或原始文件名
        if custom_names and link in custom_names:
            base_filename = custom_names[link]
        else:
            base_filename = os.path.basename(link).split('.')[0]
            
        file_name = os.path.join(output_directory, f"{base_filename}.json")
        
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

# 读取 links.txt 中的每个链接并生成对应的 JSON 文件
with open("../links.txt", 'r') as links_file:
    link_lines = links_file.read().splitlines()

links = []
custom_names = {}

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

output_dir = "./"
result_file_names = []

for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir, custom_names=custom_names)
    if result_file_name:
        result_file_names.append(result_file_name)
        print(f"成功处理: {link} -> {result_file_name}")
    else:
        print(f"处理失败: {link}")

# 打印生成的文件名总数
print(f"成功生成 {len(result_file_names)} 个文件")
