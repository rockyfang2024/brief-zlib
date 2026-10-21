#!/usr/bin/env python3
"""Read-only Z-Library entrance checks. Python 3.9+ and curl, no packages."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
AVAILABLE = {"homepage", "challenge"}


def classify(status, body, final_url, allowed_hosts):
    if urlsplit(final_url).hostname not in allowed_hosts:
        return "unconfirmed", "跳转到未核对的域名，请人工检查"
    lower = body.lower()
    if any(x in lower for x in ("parklogic.com", "domain for sale", "buy this domain", "suspected phishing", "access denied")):
        return "unconfirmed", "停放页、警告或拒绝访问页面"
    # Require the known site's automatic challenge fingerprint, not HTTP 503 alone.
    if status in (200, 403, 503) and "checking your browser" in lower and all(
        x in lower for x in ("c_token=", "c_time=", "document", "cookie")
    ):
        return "challenge", "到达站点验证页，未通过验证"
    title = re.search(r"<title[^>]*>(.*?)</title>", lower, re.S)
    if 200 <= status < 300 and title and re.search(r"z[- ]?library", title[1]):
        if re.search(r"<form\b", lower) and re.search(r"<input\b[^>]*(?:name=[\"']q[\"']|type=[\"']search[\"'])", lower):
            return "homepage", "识别到图书馆标题和搜索表单，未测试登录或下载"
    if status >= 400:
        return "http_error", f"HTTP {status}，未识别为站点验证页"
    return "unconfirmed", "页面内容不足以确认入口可用"


def probe(entry, proxy, timeout):
    with tempfile.TemporaryDirectory(prefix="brief-zlib-") as directory:
        html = Path(directory) / "body.html"
        command = ["curl", "--disable", "--silent", "--show-error", "--location",
                   "--max-redirs", "5", "--connect-timeout", str(min(10, timeout)),
                   "--max-time", str(timeout), "--compressed", "--proto", "=https",
                   "--proto-redir", "=https", "--max-filesize", "2097152",
                   "--proxy", proxy or "", "--noproxy", "" if proxy else "*",
                   "--output", str(html), "--write-out",
                   "%{http_code}\n%{url_effective}\n%{time_total}", entry["url"]]
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 5)
        checked = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if result.returncode:
            # Do not copy stderr: it can contain a proxy address or credentials.
            return {"status": "network_error", "curl_exit_code": result.returncode,
                    "detail": "请求失败或响应超过限制", "checked_at": checked}
        code, final, elapsed = result.stdout.strip().splitlines()[-3:]
        status, detail = classify(int(code), html.read_text(errors="replace"), final, entry["allowed_hosts"])
        return {"status": status, "detail": detail, "http_status": int(code),
                "final_url": final, "seconds": float(elapsed), "checked_at": checked}


def summarize(samples):
    successful = [x for x in samples if x["status"] in AVAILABLE]
    return {"available": bool(successful), "successful_attempts": len(successful),
            "attempts": len(samples), "unstable": 0 < len(successful) < len(samples),
            "median_seconds": round(statistics.median(x["seconds"] for x in successful), 3) if successful else None,
            "latest_available_at": successful[-1]["checked_at"] if successful else None,
            "samples": samples}


def load_sources(path):
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("sources 必须为 JSON 数组")
    found, enabled = set(), []
    for entry in entries:
        if not isinstance(entry, dict) or type(entry.get("enabled")) is not bool:
            raise ValueError("每个候选必须包含布尔 enabled")
        if not entry["enabled"]:
            continue
        url = entry.get("url", "")
        parsed = urlsplit(url)
        hosts = entry.get("allowed_hosts")
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.port not in (None, 443) or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            raise ValueError("候选必须是无凭据、无查询参数的 HTTPS 首页地址")
        if not isinstance(hosts, list) or not all(isinstance(h, str) and h for h in hosts) or parsed.hostname not in hosts:
            raise ValueError("allowed_hosts 必须包含入口域名")
        if not isinstance(entry.get("source"), str) or not entry["source"].startswith("https://"):
            raise ValueError("每个候选必须注明 HTTPS 来源链接")
        if url not in found:
            found.add(url)
            enabled.append(entry)
    if not enabled:
        raise ValueError("没有启用的候选地址")
    return enabled


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=ROOT / "sources.json")
    parser.add_argument("--output", type=Path, help="JSON 输出文件；默认写标准输出")
    parser.add_argument("--proxy", help="追加代理对照测试，直连测试始终执行")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=20, help="单次请求总超时秒数")
    args = parser.parse_args()
    if not 1 <= args.attempts <= 5 or not 1 <= args.timeout <= 60:
        parser.error("attempts 范围为 1–5，timeout 范围为 1–60")
    if not shutil.which("curl"):
        parser.error("需要 curl")
    if args.proxy:
        proxy = urlsplit(args.proxy)
        if proxy.scheme not in ("http", "https", "socks5", "socks5h") or not proxy.hostname:
            parser.error("代理地址格式无效")
    try:
        entries = load_sources(args.sources)
        rows = []
        for entry in entries:
            row = {"url": entry["url"], "source": entry["source"]}
            for mode, proxy in [("direct", None)] + ([("proxy", args.proxy)] if args.proxy else []):
                row[mode] = summarize([probe(entry, proxy, args.timeout) for _ in range(args.attempts)])
            row["available"] = any(row[m]["available"] for m in ("direct", "proxy") if m in row)
            rows.append(row)
        report = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "scope": "入口首页或验证页可达；direct 仅禁用显式代理，未排除 VPN/TUN/路由器代理；耗时不是浏览器完整加载时间",
                  "results": rows}
        output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0 if any(row["available"] for row in rows) else 1
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("检测未完成：" + ("请求超时" if isinstance(error, subprocess.TimeoutExpired) else str(error)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
