# sing-box-geosite

在links.txt添加规则集，自动生成 sing-box Source Format,fork后自己添加想要转换的规则集。  
---
## 格式：规则链接 文件名称

```
https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/refs/heads/main/clash.yaml AdobeBlock
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
