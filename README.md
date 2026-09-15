# sing-box-geosite

把 Clash / Surge / hosts / 纯域名列表等各种规则源，自动转换成 sing-box 的
rule-set，每天构建一次并发布到 `rule` 分支。

Fork 之后在 `links.txt` 里加自己想要的源即可。

---

## 订阅链接

```
https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/<名称>.srs
https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/<名称>.json
```

在 sing-box 配置里：

```json
{
  "type": "remote",
  "tag": "CN_Direct",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/LQ2002/sing-box-geosite/rule/CN_Direct.srs",
  "download_detour": "代理"
}
```

`tag` 是你在路由规则里引用的名字，和文件名无关，想叫什么叫什么。

### 最低 sing-box 版本

| 订阅方式 | 版本要求 |
| --- | --- |
| `.srs`（`format: binary`，推荐） | 1.10 |
| `.json`（`format: source`） | 1.14 |

生成的 json 写的是 `"version": 5`，但编译后的 **`.srs` 不受影响** ——
sing-box 会按规则实际用到的字段选最低可行的二进制版本，而不是照搬源文件的
version。当前这些规则集只用到 domain / ip_cidr 这类老字段，srs 头部仍是
`53 52 53 02`。只有真用到 v5 专有字段（如 `package_name_regex`）时才需要 1.14。

---

## 配置

### links.txt

一行一个源，格式是 `规则链接 规则集名称`：

```
https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/refs/heads/main/clash.yaml AdobeBlock
```

同名的多行会**合并**成一个规则集：

```
https://example.com/some-clash-rules.yaml   MyRule
https://example.com/already-singbox.json    MyRule
```

规则集名直接当文件名，`!` `@` `+` `~` 中文都能用，只有路径分隔符和
`: * ? " < > |` 会被替换成 `.`。

### Custom.config

往某个规则集里追加自己的域名或 IP，格式是 `域名或IP 规则集名称`：

```
dns.wechat.com BlockHttpDNS
```

---

## 支持的源格式

格式按**内容**嗅探，不看后缀，也不需要额外标注：

| 格式 | 示例 |
| --- | --- |
| Clash / Surge 规则行 | `DOMAIN-SUFFIX,example.com` |
| Clash `payload:` YAML | 常见的 ruleset yaml |
| hosts 文件 | `0.0.0.0 example.com` |
| 纯域名 / IP 列表 | 一行一个，或空格分隔 |
| sing-box 源格式 | 已经是 `{"version": N, "rules": [...]}` 的 json |
| AND / OR / NOT 复合规则 | 转成 sing-box 的 `type: logical` |
| `IP-ASN` | 构建时展开成 `ip_cidr`，见下 |

> 用 GitHub 的链接时要用 `raw.githubusercontent.com` 的地址。
> `github.com/.../blob/...` 返回的是网页，脚本会识别出来并提示正确地址。

### sing-box 源格式：原样直通

已经是 sing-box 格式的源不经过中间表示，直接拼进产物，
所以 `process_name`、`network_type`、`port_range`、`invert`、
以及 `type: logical` 的逻辑规则都能完整保留。

字段表依据 [headless rule 官方文档](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)。
表外的未知字段会被丢弃并在日志里计数 —— sing-box 对未知字段是直接报错的
（`json: unknown field "xxx"`），不过滤会让整个规则集编译失败。

### IP-ASN

sing-box 的 headless rule 没有 ASN 维度，所以 `IP-ASN` 在构建时查
[RIPEstat](https://stat.ripe.net/) 的 BGP 宣告表，展开成 `ip_cidr`：

```
IP-ASN,399358,PROXY
  -> {"ip_cidr": ["160.79.104.0/23", "2607:6bc0::/48", "2607:6bc0:11::/48"]}
```

`399358`、`AS399358`、`as399358` 三种写法都认。复合规则里也能用：

```
AND,((IP-ASN,399358),(DOMAIN-SUFFIX,anthropic.com)),PROXY
```

几点注意：

- **前缀是会变的**，展开的是构建当天的快照。这个仓库每天重建一次，所以会跟着更新
- 大型 ASN 的前缀不少（Cloudflare AS13335 约 5400 条，China Telecom AS4134 约 1400 条），会显著增大规则集
- 同一个 ASN 在一次构建里只查一次
- **查不到就让整个规则集失败**。ASN 往往代表一整家服务商的网段，
  静默少掉它会让规则悄悄失效，不如让 CI 跳过这次发布、保留上一版完整快照

### 复合规则

```
AND,((DOMAIN,ads.example.com),(DEST-PORT,80)),REJECT
  -> {"type":"logical","mode":"and","rules":[{"domain":["ads.example.com"]},{"port":[80]}]}

NOT,((DOMAIN,allow.example.com)),REJECT
  -> {"type":"logical","mode":"and","rules":[...],"invert":true}
```

支持嵌套。如果某个分量 sing-box 没有对应字段（如 `IP-ASN`、`GEOSITE`），
处理方式取决于**丢掉它会让规则变宽还是变窄**：

- 变宽 → **整条丢弃**。匹配到本不该匹配的流量，比漏掉一条规则危险得多
- 变窄 → 保留剩下的

`AND` 少一个条件是变宽，`OR` 少一个条件是变窄，而 `NOT` / `invert` 会把两者对调。
两种情况都会在日志里说明。

---

## {tag} 占位符

对齐 sing-box [rule-set 的多 tag 语义](https://sing-box.sagernet.org/zh/configuration/rule-set/)：
第二列写成逗号分隔的标签，url 里的 `{tag}` 会被替换成每个标签，
一行展开成多个规则集。标签同时就是各自的规则集名。

```
https://example.com/rule/{tag}.json    360,115,google
  -> 360.json / 115.json / google.json 三个规则集
```

`{tag}` 可以在 url 里出现多次，会全部替换：

```
https://example.com/{tag}/list-{tag}.txt    a,b
  -> https://example.com/a/list-a.txt   规则集 a
  -> https://example.com/b/list-b.txt   规则集 b
```

### 后缀不一样怎么办

因为格式是按内容嗅探的，`{tag}.json`、`{tag}.list`、`{tag}.yaml`、
甚至模板里不写后缀，都能用：

```
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/{tag}/{tag}.yaml    Telegram,YouTube
https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/Lists/{tag}                      Microsoft,Tracking
```

如果同一行里各个文件的后缀**不一样**，把模板写到 `{tag}` 为止，
后缀跟在标签上，规则集名会自动剥掉它：

```
https://example.com/rule/{tag}    360.json,115.list,google.hosts,plain
  -> rule/360.json     规则集 360
  -> rule/115.list     规则集 115
  -> rule/google.hosts 规则集 google
  -> rule/plain        规则集 plain
```

会被剥掉的后缀是固定一组：`.json` `.list` `.txt` `.yaml` `.yml`
`.conf` `.srs` `.hosts` `.rules`（不区分大小写）。不在表里的不动，
所以 `v2.ray` 这种本身带点的标签不会被误伤。

几条约束：

- 设了多个标签却没有 `{tag}` 占位符 → 该行跳过并提示
- 有 `{tag}` 却没给标签 → 该行跳过并提示
- 标签不能含空白或 `/ \ : * ? " < > |`
- 展开出的名字和普通行一样参与合并，也一样吃 Custom.config

---

## 构建与发布

CI 在 push 到 main、每天 04:00 UTC、以及手动触发时运行，产物强制覆盖到
`rule` 分支。

`rule` 是一个**孤儿分支，永远只有一个提交**，所以仓库不会因为累积二进制
历史而膨胀（`.srs` 是 zlib 压缩的，git 既不能 delta 也压不动）。
不要往这个分支提交东西，下次构建就没了。

生成不完整时（某个上游源挂了）CI 会**跳过这次发布**，保留上一版完整快照 ——
强制覆盖会让缺失的文件从分支上消失，订阅立刻 404。

### 仓库设置

Settings → Actions → General → Workflow permissions → 勾选
**Read and write permissions**（CI 需要写 `rule` 分支）。

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
