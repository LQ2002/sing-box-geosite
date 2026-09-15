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

sing-box 源格式的链接采用**原样直通**：不转换成中间表示，
所以 `process_name`、`network_type`、`port_range`、`invert`、
以及 `type: logical` 的逻辑规则都能完整保留。

字段表依据 [headless rule 官方文档](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)，
表外的未知字段会被丢弃并在日志里计数 ——
sing-box 对未知字段是直接报错的（`json: unknown field "xxx"`），
不过滤会让整个规则集编译失败。

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
