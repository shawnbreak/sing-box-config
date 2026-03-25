# sing-box-config

```
usage: parse [-h] [--url URL] [--update]

sing box parse

options:
  -h, --help  show this help message and exit
  --url URL
  --update
```


# Request google.com example

```
app → DNS请求
→ route.rule(hijack-dns)
→ dns.rule(final)
→ detour = proxy
→ 1.1.1.1 查询
→ 返回国外 IP

app → 访问 IP
→ route.rule(非国内)
→ proxy
```


# Request baidu.com example

```
app → DNS请求
→ hijack-dns
→ dns.rule(geosite-cn)
→ detour = direct
→ 国内 DNS 查询（你写的是 233.5.5.5，这里应该是 typo）

app → 访问 IP
→ route.rule(国内IP)
→ direct
```
