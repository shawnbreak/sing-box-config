import urllib
import base64
import json
import re
import logging

logger = logging.getLogger(__name__)

def _parse_anytls(parse_result: urllib.parse.ParseResult) -> tuple[dict, str]:
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
    
def _parse_ss(parse_result: urllib.parse.ParseResult) -> tuple[dict, str]:
    querys = urllib.parse.parse_qs(parse_result.query)
    tag = urllib.parse.unquote(parse_result.fragment)
    method_and_pwd = base64.b64decode(parse_result.username).decode("utf-8")
    method = method_and_pwd.split(":")[0]
    pwd = method_and_pwd.split(":")[1]
    outbound = {
        "type": "shadowsocks" if parse_result.scheme == "ss" else parse_result.scheme,
        "tag": tag,
        "server": parse_result.hostname,
        "server_port": int(parse_result.port),
        "method": method,
        "password": pwd,
    }
    return outbound, tag

def _parse_vmess(line: str) -> tuple[dict, str]:
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


def _parse_vless(parse_result: urllib.parse.ParseResult) -> tuple[dict, str]:
    """
    vless://uuid@host:port?security=reality&flow=xtls-rprx-vision&...#tag

    支持 security: none / tls / reality，transport: tcp / ws / grpc / http / httpupgrade
    """
    querys = urllib.parse.parse_qs(parse_result.query, keep_blank_values=True)

    def q(key: str, default: str = "") -> str:
        return querys.get(key, [default])[0] or default

    tag = urllib.parse.unquote(parse_result.fragment)
    if not tag:
        tag = f"{parse_result.hostname}:{parse_result.port}"

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": parse_result.hostname,
        "server_port": int(parse_result.port),
        "uuid": urllib.parse.unquote(parse_result.username or ""),
    }

    # flow 仅 tcp + vision 场景使用
    flow = q("flow")
    if flow:
        outbound["flow"] = flow

    # encryption 固定为 none，sing-box 无需该字段
    if q("encryption", "none") != "none":
        logger.warning(f"vless {tag}: unsupported encryption {q('encryption')}")

    network = q("type", "tcp")
    security = q("security", "none")

    if security in ("tls", "reality", "xtls"):
        tls: dict = {"enabled": True}
        sni = q("sni") or q("host")
        if sni:
            tls["server_name"] = sni

        fingerprint = q("fp")
        if fingerprint and fingerprint != "none":
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

        alpn = q("alpn")
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]

        if q("insecure") in ("1", "true") or q("allowInsecure") in ("1", "true"):
            tls["insecure"] = True

        if security == "reality":
            reality = {"enabled": True, "public_key": q("pbk")}
            if q("sid"):
                reality["short_id"] = q("sid")
            tls["reality"] = reality

        outbound["tls"] = tls

    transport = _parse_vless_transport(network, q)
    if transport:
        outbound["transport"] = transport

    # udp 封装方式，xudp 兼容性更好
    packet_encoding = q("packetEncoding")
    if packet_encoding in ("xudp", "packetaddr"):
        outbound["packet_encoding"] = packet_encoding

    return outbound, tag


def _parse_vless_transport(network: str, q) -> dict | None:
    host = q("host")
    path = q("path")
    # tcp + headerType=http 等价于 http 伪装
    if network == "tcp" and q("headerType") == "http":
        network = "http"
    elif network == "tcp":
        return None

    if network == "ws":
        transport = {"type": "ws", "path": path or "/"}
        if host:
            transport["headers"] = {"Host": host}
        return transport

    if network == "grpc":
        return {"type": "grpc", "service_name": q("serviceName")}

    if network == "http":
        transport = {"type": "http", "path": path or "/"}
        if host:
            transport["host"] = [h for h in host.split(",") if h]
        return transport

    if network == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path or "/"}
        if host:
            transport["host"] = host
        return transport

    return None


parsers = {
    "ss": _parse_ss,
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "anytls": _parse_anytls
}
