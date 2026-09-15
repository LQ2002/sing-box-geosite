# sing-box-geosite

在links.txt添加规则集，自动生成 sing-box Source Format,fork后自己添加想要转换的规则集。  
---
## 格式：规则链接 文件名称

```
https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/refs/heads/main/clash.yaml AdobeBlock
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

规则集不再提交到仓库，由 CI 发布到 `latest` 这个滚动 Release，**每次构建覆盖旧文件**，仓库体积恒定。

```
https://github.com/LQ2002/sing-box-geosite/releases/latest/download/<名称>.srs
https://github.com/LQ2002/sing-box-geosite/releases/latest/download/<名称>.json
```

例如：

```
https://github.com/LQ2002/sing-box-geosite/releases/latest/download/Ads_SKK.srs
https://github.com/LQ2002/sing-box-geosite/releases/latest/download/CN_Direct.srs
```

在 sing-box 配置里：

```json
{
  "type": "remote",
  "tag": "Ads_SKK",
  "format": "binary",
  "url": "https://github.com/LQ2002/sing-box-geosite/releases/latest/download/Ads_SKK.srs",
  "download_detour": "代理"
}
```

> 旧的 `raw.githubusercontent.com/.../main/rule/xxx.srs` 链接已失效，请改用上方地址。

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
