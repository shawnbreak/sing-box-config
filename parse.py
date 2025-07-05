#!/usr/bin/python3

import requests
import base64
import urllib.parse
import re
import json

# sing-box examples
# https://github.com/chika0801/sing-box-examples

config_temp = "./sing-box_1.11.json"

with open("orig", "r") as f:
    raw = f.read().rstrip('\n')

padding = len(raw) % 4
if padding:
    raw += "=" * (4 - padding)

decode_str = base64.b64decode(raw.encode("utf-8")).decode("utf-8")
decode_lines = decode_str.split("\n")

pattern_ss = re.compile("(.*)://(.*)@(.*):(.*)#(.*)")
pattern_vmess = re.compile("(.*)://(.*)")
outbounds = []
outbound_tags = []
for line in decode_lines:
    if line and line.startswith("ss"):
        r = urllib.parse.unquote(line)
        match = pattern_ss.match(r)
        otype = match.group(1)
        method_and_pwd = match.group(2)
        url = match.group(3)
        port = match.group(4)
        tag = match.group(5).rstrip("\r")
        method_and_pwd = base64.b64decode(method_and_pwd.encode("utf-8")).decode("utf-8").split(":")
        method = method_and_pwd[0]
        pwd = method_and_pwd[1]
        outbound = {
                "type": "shadowsocks" if otype == "ss" else otype,
                "tag": tag,
                "server": url,
                "server_port": int(port),
                "method": method,
                "password": pwd
        }
        outbounds.append(outbound)
        outbound_tags.append(tag)
    elif line and line.startswith("vmess"):
        match = pattern_vmess.match(line)
        otype = match.group(1)
        content_raw = match.group(2)
        content = base64.b64decode(content_raw).decode("utf-8")
        content = json.loads(content)
        host = content["host"]
        add = content["add"]
        id = content["id"]
        net = content["net"]
        path = content["path"]
        port = int(content["port"])
        ps = content["ps"]
        aid = content["aid"]
        outbound = {
                "type": otype,
                "tag": ps,
                "alter_id": aid,
                "network": "tcp",
                "security": "auto",
                "server": add,
                "server_port": port,
                "transport": {
                    "path": path,
                    "type": net
                },
                "uuid": id
        }
        outbounds.append(outbound)
        outbound_tags.append(ps)

#print(json.dumps(outbounds, ensure_ascii=False, indent=4))
#print(json.dumps(outbound_tags, ensure_ascii=False, indent=4))

with open(config_temp, "r") as f:
    temp = json.loads(f.read())

temp_outbounds = temp["outbounds"]
for o in temp_outbounds:
    if o["tag"] == "proxy":
        o["outbounds"] = outbound_tags
    if o["tag"] == "auto":
        o["outbounds"] = outbound_tags

for o in outbounds:
    temp_outbounds.append(o)

result = json.dumps(temp, indent=4, ensure_ascii=False)
with open("config.json", "w") as f:
    f.write(result)


