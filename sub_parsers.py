import urllib

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


parsers = {
    "ss": _parse_ss,
    "vmess": _parse_vmess,
    "anytls": _parse_anytls
}
