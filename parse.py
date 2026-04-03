#!/usr/bin/python3

import sys
from typing import List, Tuple
import requests
import base64
import urllib.parse
import re
import json
import argparse
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

logger.info("start parse")

# sing-box examples
# https://github.com/chika0801/sing-box-examples
config_temp = "./sing-box_1.13.json"
config_result = "config.json"
cache_file=".cache_content"
cache_url=".cache_url"

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
}

def parse_args() -> Tuple[str, bool, bool, bool]:
    parse = argparse.ArgumentParser(
        prog="parse",
        description="sing box parse"
    )

    parse.add_argument("--url")
    parse.add_argument("--update", action='store_true', default=False)
    parse.add_argument("--tun", action='store_true', default=False)
    parse.add_argument("--mixed", action='store_true', default=False)
    
    args = parse.parse_args()
    return args.url, args.update, args.tun, args.mixed

def get_sub_raw(update: bool, url: str):
    if url:
        logger.info("cache url")
        with open(cache_url, "w") as f:
            f.write(url)

    with open(cache_url, "r") as f:
        url = f.read()

    if update:
        logger.info(f"update content from {url}")
        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            print(f"ERROR: http status code: {res.status_code}")
            print(res.text)
            sys.exit(1)
        with open(cache_file, "w") as f:
            f.write(res.text)

    with open(cache_file, "r") as f:
        raw = f.read().rstrip('\n')
        return raw

def check_pad(raw: str) -> str:
    padding = len(raw) % 4
    if padding:
        raw += "=" * (4 - padding)
    return raw

def decode_as_lines(raw: str) -> List[str]:
    decode_str = base64.b64decode(raw.encode("utf-8")).decode("utf-8")
    decode_lines = decode_str.split("\n")
    return decode_lines

def _parse_anytls(parse_result: urllib.parse.ParseResult) -> Tuple[dict, str]:
    #anytls://ba2d7144-2992-4383-8a8d-9b3983160424@id01.shanhai.cfd:14401/?type=tcp&insecure=0&fp=chrome&sni=id01.shanhai.sbs#%E5%8D%B0%E5%BA%A6%E5%B0%BC%E8%A5%BF%E4%BA%9A01%5B%E4%B8%93%E7%BA%BF%5D1.0
    querys = urllib.parse.parse_qs(parse_result.query)
    tag = urllib.parse.unquote(parse_result.fragment)
    return {
        "type": parse_result.scheme,
        "tag":  tag,
        "server": parse_result.hostname,
	"server_port": int(parse_result.port),
	"password": parse_result.username,
	"tls": {
	    "enabled": True,
	    "server_name": querys.get("sni")[0],
	    "utls": {
		"enabled": True,
		"fingerprint": "chrome"
	    },
	    "insecure": False
	}
    }, tag
    
def _parse_ss(line: str) -> Tuple[dict, str]:
    pattern_ss = re.compile("(.*)://(.*)@(.*):(.*)#(.*)")
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
        "password": pwd,
    }
    return outbound, tag

def _parse_vmess(line: str) -> Tuple[dict, str]:
    pattern_vmess = re.compile("(.*)://(.*)")
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
    aid = int(content["aid"])
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
    return outbound, ps

def parse_lines(decode_lines: List[str]) -> Tuple[List[dict], List[str]]:
    outbounds = []
    outbound_tags = []
    for line in decode_lines:
        if not line:
            continue
        try:
            parse_result: urllib.parse.ParseResult = urllib.parse.urlparse(line)
            if parse_result.scheme == "ss":
                outbound, tag = _parse_ss(line)
            elif parse_result.scheme == "vmess":
                outbound, tag = _parse_vmess(line)
            elif parse_result.scheme == "anytls":
                outbound, tag = _parse_anytls(parse_result)
            else:
                logger.warning(f"cannot parse {line}")
                continue
        except Exception as e:
            logger.error(f"{e}")
            continue

        if tag not in outbound_tags:
            outbounds.append(outbound)
            outbound_tags.append(tag)
    return outbounds, outbound_tags


def read_template(template_file: str) -> dict:
    with open(template_file, "r") as f:
        temp = json.loads(f.read())
    return temp


ai_exclude_tag_pattern = [ "香港", "台湾", "菲律宾" ]
def fill_template(template: dict, outbounds: List[dict], outbound_tags: List[str], tun: bool, mixed: bool) -> dict:
    temp_inbounds = template["inbounds"]
    inbounds = []
    for i in temp_inbounds:
        if i["type"] == "tun" and tun:
            inbounds.append(i)
        if i["type"] == "mixed" and mixed:
            inbounds.append(i)
    template["inbounds"] = inbounds
    temp_outbounds = template["outbounds"]
    for o in temp_outbounds:
        if o["tag"] == "proxy":
            o["outbounds"] = ["auto"]
            for t in  outbound_tags:
                o["outbounds"].append(t)

        if o["tag"] == "auto":
            o["outbounds"] = outbound_tags
        if o["tag"] == "ai":
            ai_tags = []
            for t in outbound_tags:
                t_ok = True
                for et in ai_exclude_tag_pattern:
                    if et in t:
                        t_ok = False
                        break
                if t_ok:
                    ai_tags.append(t)

            o["outbounds"] = ai_tags

    for o in outbounds:
        temp_outbounds.append(o)

    return template

def write_config(config_result: str, template: dict):
    result = json.dumps(template, indent=4, ensure_ascii=False)
    with open(config_result, "w") as f:
        f.write(result)

def main():
    url, update, tun, mixed = parse_args()
    raw = get_sub_raw(update, url)
    raw = check_pad(raw)
    lines = decode_as_lines(raw)
    outbounds, outbound_tags = parse_lines(lines)
    count = len(outbound_tags)
    logger.info(outbound_tags)
    logger.info(f"total nodes: {count}")
    template = read_template(config_temp)
    result = fill_template(template, outbounds, outbound_tags, tun, mixed)
    write_config(config_result, result)

if __name__ == "__main__":
    main()
