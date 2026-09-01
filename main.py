#!/usr/bin/python3

import os
import sys
from typing import List, Tuple
import requests
import base64
import urllib.parse
import re
import json
import argparse
import logging
from sub_parsers import parsers

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

logger.info("start parse")

# sing-box examples
# https://github.com/chika0801/sing-box-examples
config_temp = "./sing-box_1.13.json"
config_result = "config.json"
sub_config = "./sub.json"

ai_exclude_tag_pattern = [ "香港", "台湾", "菲律宾" ]

# urltest 测速排除的节点地区（质量不稳定/距离过远，避免测速选中烂节点）
urltest_exclude_tag_pattern = [
    "尼日利亚", "安哥拉", "埃及", "摩洛哥", "南非",          # 非洲
    "伊拉克", "卡塔尔", "阿曼", "沙特阿拉伯", "阿联酋", "以色列", "塞浦路斯", "土耳其", "格鲁吉亚",  # 中东
    "哈萨克斯坦", "乌兹别克斯坦", "巴基斯坦", "孟加拉", "尼泊尔",  # 中亚/南亚
    "巴西", "墨西哥", "阿根廷", "智利", "哥伦比亚", "秘鲁", "厄瓜多尔", "哥斯达黎加", "乌拉圭",  # 拉美
    "俄罗斯", "乌克兰", "摩尔多瓦", "马其顿", "阿尔巴尼亚", "塞尔维亚", "罗马尼亚", "保加利亚",
    "立陶宛", "拉脱维亚", "爱沙尼亚", "斯洛文尼亚", "克罗地亚", "冰岛", "卢森堡",  # 东欧/巴尔干/小国
]


def is_excluded(tag: str, patterns: List[str]) -> bool:
    return any(p in tag for p in patterns)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
}

def parse_args() -> Tuple[bool, bool, bool]:
    parse = argparse.ArgumentParser(
        prog="parse",
        description="sing box parse"
    )

    parse.add_argument("--update", action='store_true', default=False)
    parse.add_argument("--tun", action='store_true', default=False)
    parse.add_argument("--mixed", action='store_true', default=False)

    args = parse.parse_args()
    return args.update, args.tun, args.mixed

def get_sub_raw(sub_name: str, url: str, update: bool):
    cache_file = f".cache_{sub_name}"
    if not os.path.exists(cache_file):
        update = True

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
    """
    base64 encoded string's length should divided by 4, if not enough, padding with =
    some subsccription will ignore trailing =, so we check and add the pad.
    """
    padding = len(raw) % 4
    if padding:
        raw += "=" * (4 - padding)
    return raw

def decode_as_lines(raw: str) -> List[str]:
    decode_str = base64.b64decode(raw.encode("utf-8")).decode("utf-8")
    decode_lines = decode_str.split("\n")
    return decode_lines


def parse_lines(decode_lines: List[str]) -> Tuple[List[dict], List[str]]:
    outbounds = []
    outbound_tags = []
    for line in decode_lines:
        if not line:
            continue

        try:
            parse_result: urllib.parse.ParseResult = urllib.parse.urlparse(line)
            parser = parsers.get(parse_result.scheme)
            if parser:
                outbound, tag = parser(parse_result)
            else:
                logger.warning(f"cannot parse {parse_result.scheme}")
                continue
        except Exception as e:
            logger.error(f"{e}")
            continue

        if tag not in outbound_tags:
            outbounds.append(outbound)
            outbound_tags.append(tag)
    return outbounds, outbound_tags

def parse_sub(sub_name, sub_url, update):

    raw = get_sub_raw(sub_name, sub_url, update)
    raw = check_pad(raw)
    lines = decode_as_lines(raw)
    outbounds, outbound_tags = parse_lines(lines)
    return outbounds, outbound_tags

def main():
    update, tun, mixed = parse_args()
    with open(sub_config, "r") as f:
        sub_config_content = f.read()
        sub_json = json.loads(sub_config_content)

    subs = sub_json.get("subs")

    """
    outbounds: [
       {
         tag: proxy, type: selector
       },
       {
         tag: byg, type: urltest
       },
       {
          tag: ai, type: selector
       },
       {
          tag: ai_urltest: type: urltest
       }
    ]
    """
    outbounds = []
    proxy_outbounds = []
    ai_outbounds = []
    subs_outbounds = []

    for sub in subs:
        if not sub.get("active"):
            continue
        sub_name = sub.get("name")
        sub_url = sub.get("sub_url")
        sub_outbounds, sub_outbound_tags = parse_sub(sub_name, sub_url, update)
        for o in sub_outbounds:
            subs_outbounds.append(o)
        logger.info(f"{sub_name}: {len(sub_outbounds)}\n{[s.get('tag') for s in sub_outbounds]}")


    proxy_outbounds.extend([s.get("tag") for s in subs_outbounds])

    # ai 出站候选：排除 ai_exclude_tag_pattern 指定地区
    ai_outbounds = [s.get("tag") for s in subs_outbounds
                    if not is_excluded(s.get("tag"), ai_exclude_tag_pattern)]

    # urltest 测速候选：再排除质量不稳定的远距离节点
    proxy_urltest_outbounds = [t for t in proxy_outbounds
                               if not is_excluded(t, urltest_exclude_tag_pattern)]
    ai_urltest_outbounds = [t for t in ai_outbounds
                            if not is_excluded(t, urltest_exclude_tag_pattern)]

    outbounds.append({
	"type": "direct",
	"tag": "direct",
	"domain_resolver": "local-dns"
    })

    outbounds.append({
        "type": "selector",
	"tag": "proxy",
	"outbounds": ["proxy_urltest"] + proxy_outbounds
    })

    outbounds.append({
        "type": "urltest",
	"tag": "proxy_urltest",
        "interval": "3m",
        "tolerance": 200,
	"outbounds": proxy_urltest_outbounds
    })

    outbounds.append({
	"type": "selector",
	"tag": "ai",
	"outbounds": ["ai_urltest"] + ai_outbounds
    })

    outbounds.append({
	"type": "urltest",
	"tag": "ai_urltest",
        "interval": "3m",
        "tolerance": 200,
        "url": "https://cp.cloudflare.com/generate_204",
	"outbounds": ai_urltest_outbounds
    })

    outbounds.extend(subs_outbounds)

    with open(config_temp, "r") as f:
        template = json.loads(f.read())

    temp_inbounds = template["inbounds"]
    inbounds = []
    for i in temp_inbounds:
        if i["type"] == "tun" and tun:
            inbounds.append(i)
        if i["type"] == "mixed" and mixed:
            inbounds.append(i)
    template["inbounds"] = inbounds
    template["outbounds"] = outbounds

    with open(config_result, "w") as f:
        f.write(json.dumps(template, indent=4, ensure_ascii=False))


if __name__ == "__main__":
    main()
