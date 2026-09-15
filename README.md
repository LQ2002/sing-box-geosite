# sing-box-geosite

在links.txt添加规则集，自动生成 sing-box Source Format,fork后自己添加想要转换的规则集。  
---
## 格式：规则链接 文件名称

```
https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/refs/heads/main/clash.yaml AdobeBlock
```

## {tag} 占位符

对齐 sing-box [rule-set 的多 tag 语义](https://sing-box.sagernet.org/zh/configuration/rule-set/)：
第二列写成逗号分隔的标签，url 里的 `{tag}` 会被替换成每个标签，
一行展开成多个规则集。标签同时就是各自的规则集名。

```
https://example.com/rule/{tag}.json    360,115,google
```

会分别拉取 `360.json`、`115.json`、`google.json`，
生成 `360.srs`、`115.srs`、`google.srs` 三个规则集。

`{tag}` 可以在 url 里出现多次，会全部替换：

```
https://example.com/{tag}/list-{tag}.txt    a,b
  -> https://example.com/a/list-a.txt   规则集 a
  -> https://example.com/b/list-b.txt   规则集 b
```

### 后缀不一样怎么办

格式是按**内容**嵌探的，不看后缀，所以 `{tag}.json`、`{tag}.list`、
`{tag}.yaml`、甚至模板里不写后缀都能用：

```
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/{tag}/{tag}.yaml    Telegram,YouTube
https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/Lists/{tag}                      Microsoft,Tracking
```

如果同一行里各个文件的后缀不一样，把模板写到 `{tag}` 为止，
后缀跟在标签上，规则集名会自动剥掉它：

```
https://example.com/rule/{tag}    360.json,115.list,google.hosts,plain
  -> rule/360.json     规则集 360      (sing-box 源格式)
  -> rule/115.list     规则集 115      (Clash/Surge 规则行)
  -> rule/google.hosts 规则集 google   (hosts 文件)
  -> rule/plain        规则集 plain    (纯域名列表)
```

会被剥掉的后缀是固定的一组：`.json` `.list` `.txt` `.yaml` `.yml`
`.conf` `.srs` `.hosts` `.rules`（不区分大小写）。不在表里的不动，
所以 `v2.ray` 这种本身带点的标签不会被误伤。

几条约束：

- 设了多个标签却没有 `{tag}` 占位符 → 该行跳过并提示
- 有 `{tag}` 却没给标签 → 该行跳过并提示
- 标签会当文件名用，只允许字母、数字和 `_ . @ + -`，其余跳过
- 展开出的名字和普通行一样参与合并，也一样吃 Custom.config

```
https://example.com/rule/{tag}.json    Alipay,WeChat
https://example.com/extra-wechat.list  WeChat     # 会合并进 WeChat
```

## 规则名的可用字符

规则名直接当文件名，几乎不受限制 —— `!` `@` `+` `~` 空格、中文都能用。
脚本只替换文件系统真正不接受的字符：路径分隔符和 `: * ? " < > |` 以及控制字符。

```
Ai-Global!cn   ->  Ai-Global!cn      原样保留
中文规则        ->  中文规则           也能用
a/b            ->  a.b               路径分隔符不行
a:b  a*b  a|b  ->  a.b
```

## 支持的源格式

links.txt 里的链接会自动识别格式，无需额外标注：

| 格式 | 说明 |
| --- | --- |
| Clash / Surge 规则列表 | `DOMAIN-SUFFIX,example.com` 这类写法 |
| Clash `payload:` YAML | 常见的 ruleset yaml |
| hosts 文件 | `0.0.0.0 example.com` |
| 纯域名 / IP 列表 | 一行一个，或空格分隔 |
| **sing-box 源格式** | 已经是 `{"version": N, "rules": [...]}` 的 json |
| AND / OR / NOT 复合规则 | Surge、Clash 的逻辑规则，转成 sing-box 的 `type: logical` |

sing-box 源格式的链接采用**原样直通**：不转换成中间表示，
所以 `process_name`、`network_type`、`port_range`、`invert`、
以及 `type: logical` 的逻辑规则都能完整保留。

字段表依据 [headless rule 官方文档](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)，
表外的未知字段会被丢弃并在日志里计数 ——
sing-box 对未知字段是直接报错的（`json: unknown field "xxx"`），
不过滤会让整个规则集编译失败。

### 复合规则

```
AND,((DOMAIN,ads.example.com),(DEST-PORT,80)),REJECT
  -> {"type":"logical","mode":"and","rules":[{"domain":["ads.example.com"]},{"port":[80]}]}

NOT,((DOMAIN,allow.example.com)),REJECT
  -> {"type":"logical","mode":"and","rules":[...],"invert":true}
```

支持嵌套。分量里的类型如果 sing-box 没有对应字段（如 `IP-ASN`、`GEOSITE`）：

- **AND / NOT 整条丢弃** —— 少一个条件会让规则变宽，匹配到本不该匹配的流量，比丢规则更危险
- **OR 保留剩余分量** —— 只会变窄，是安全的

两种情况都会在日志里说明。

同一个规则名下可以混用多种格式的源，会合并成一个文件：

```
https://example.com/some-clash-rules.yaml   MyRule
https://example.com/already-singbox.json    MyRule
```

## 在Custom.config里添加域名/ip和规则链接名称  
```
dns.wechat.com BlockHttpDNS
```

## 订阅链接

规则集不进 main 分支，CI 把产物发布到 `rule` 分支：

```
https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/<名称>.srs
https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/<名称>.json
```

例如：

```
https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/Ai-Global!cn.srs
https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/CN_Direct.srs
```

`rule` 是一个孤儿分支，每次构建强制覆盖，**永远只有一个提交**，
所以仓库不会因为累积历史而膨胀。不要往这个分支提交东西，下次构建就没了。
生成不完整时（某个上游源挂了）CI 会跳过这次发布，保留上一版完整快照。

### 在 sing-box 配置里

```json
{
  "type": "remote",
  "tag": "Ai-Global!cn",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/Ai-Global!cn.srs",
  "download_detour": "代理"
}
```

`tag` 是你在路由规则里引用的名字，和文件名无关，想叫什么叫什么。

> 早先用过的 `.../main/rule/xxx.srs` 和 GitHub Releases 的
> `releases/latest/download/xxx.srs` 链接都已废弃。

### 版本要求

生成的 json 写的是 `"version": 5`（`main.py` 里的 `RULE_SET_VERSION`）。

但编译后的 **`.srs` 不受影响** —— sing-box 会按规则实际用到的字段
选择最低可行的二进制版本，而不是照搬源文件的 version。
当前这几个规则集只用了 domain / ip_cidr 这些老字段，
编译出来的 srs 头部仍是 `53 52 53 02`（sing-box >= 1.10 即可）。

| 订阅方式 | 最低 sing-box 版本 |
| --- | --- |
| `.srs`（`format: binary`，推荐） | 1.10 |
| `.json`（`format: source`） | 1.14 |

只有当规则真用到 v5 专有字段（如 `package_name_regex`）时，
srs 头部才会变成 `53 52 53 05`，那时才需要 1.14。

## 仓库机器人权限  

仓库 Settings ----> Actions ----> General ----> Workflow permissions ----> Read and write permissions 勾选上（发布 Release 需要写权限）  
---

# 致谢（排名不分先后）

[@izumiChan16](https://github.com/izumiChan16)

[@ifaintad](https://github.com/ifaintad)

[@NobyDa](https://github.com/NobyDa)

[@blackmatrix7](https://github.com/blackmatrix7)

[@DivineEngine](https://github.com/DivineEngine)  

[@Toperlock](https://github.com/Toperlock/sing-box-geosite)  

[@Claude](https://claude.ai)

[@ShadowWhisperer](https://github.com/ShadowWhisperer)
