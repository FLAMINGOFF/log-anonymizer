#!/usr/bin/env python3
"""
日志脱敏工具 (Log Anonymizer)

把日志里的 IP 地址（IPv4/IPv6）、邮箱、MAC 地址、用户名替换成假名，
而且同一个值永远映射到同一个假名：
    203.0.113.7 第一次出现变成 10.83.21.190，之后每次出现都还是 10.83.21.190，
这样脱敏后的日志仍然能分析（"同一个 IP 先爆破 ssh 再登录成功"这种关联不会丢）。

假名用 HMAC-SHA256(密钥, 原值) 推导：有密钥才能算出对应关系，
没有密钥的人拿到脱敏日志也没法通过"把所有 IP 都哈希一遍"来反查。
可选 --map 把映射表存成 JSON，下次运行继续沿用，也能用 --reverse 还原。

只依赖 Python 标准库，Python 3.8+。
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
from collections import Counter
from typing import Dict, Iterable, List, Optional, Tuple

KINDS = ("email", "ipv4", "ipv6", "mac", "user")
KIND_LABELS = {
    "email": "邮箱",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "mac": "MAC",
    "user": "用户名",
}
KEY_ENV = "LOG_ANON_KEY"

# ---------------------------------------------------------------- 识别规则

EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![\w-])"
)
# 四段 0-255；前后不能紧挨着数字或"数字."（避免把 1.2.3.4.5 这种版本号拆出一截）
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\.?\d)")
# IPv6 很难用一个正则写对：先宽松地找候选（十六进制 + 冒号，可带 IPv4 尾巴和 %zone），
# 再交给 ipaddress 校验。时间戳 12:34:56 不是合法 IPv6，会被过滤掉。
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?:%[\w.-]+)?(?![\w:])"
)
MAC_RE = re.compile(r"(?<![\w:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])")

# 用户名没有固定格式，只能靠上下文：key=value、sshd/sudo 的固定句式、家目录路径
_UVAL = r"([^\s\"',;&()\[\]{}<>]+)"
USER_CONTEXT_RES = [
    # user=frank  username: frank  "user":"frank"  login=frank  account=frank
    re.compile(
        r"(?i)(?<![\w-])[\"']?(?:user(?:_?name)?|login|account|acct|uname|owner)[\"']?\s*[=:]\s*[\"']?" + _UVAL
    ),
    # sshd: Invalid user admin from ... / Connection closed by authenticating user root ...
    re.compile(r"(?i)\b(?:invalid|illegal|authenticating)\s+user\s+" + _UVAL),
    # sshd: Accepted publickey for frank from ...  / Failed password for root from ...
    re.compile(r"\bfor\s+(?:invalid\s+user\s+)?" + _UVAL + r"\s+from\b"),
    # pam: session opened for user frank(uid=1000) by ...
    re.compile(r"(?i)\bfor\s+user\s+" + _UVAL),
    # sudo:    frank : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=...
    re.compile(r"\bsudo(?:\[\d+\])?:\s+" + _UVAL + r"\s+:"),
    # /home/frank/...  /Users/frank/...  C:\Users\frank\...
    re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\Users\\)([^/\\\s\"',;:]+)"),
]
# 这些词出现在 user= 后面也不是真实用户名，不替换
USER_STOPWORDS = {
    "-", "--", "unknown", "none", "null", "nil", "n/a", "na", "undefined",
    "true", "false", "invalid", "user", "from", "by", "for",
}
USER_TRAILING_PUNCT = ".:!?"
# 学到的用户名在全文按整词替换时，太短的会误伤正常单词（比如 "a"），跳过
MIN_LEARNED_USER_LEN = 3


def _clean_user(value: str) -> Optional[str]:
    value = value.rstrip(USER_TRAILING_PUNCT)
    if not value or value.lower() in USER_STOPWORDS:
        return None
    if value.isdigit():  # uid=1000 这类纯数字不是用户名
        return None
    return value


def _valid_ipv6(text: str) -> Optional[str]:
    """候选串是合法 IPv6 就返回规范写法（压缩形式、小写），否则 None。"""
    addr, _, zone = text.partition("%")
    if addr.count(":") < 2 or not re.search(r"[0-9A-Fa-f]", addr):
        return None
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return None
    return ip.compressed + (f"%{zone}" if zone else "")


# --keep-private 保留的"内网"范围。不用 ipaddress 的 is_private，
# 因为它把文档示例段（203.0.113.0/24 等）也算作 private
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",  # RFC 1918 + CGNAT
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32",
    "::1/128", "::/128", "fe80::/10", "fc00::/7",
)]


def is_internal(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.partition("%")[0])
    return any(ip.version == n.version and ip in n for n in INTERNAL_NETS)


# ---------------------------------------------------------------- 假名生成


class Pseudonymizer:
    """负责"原值 → 假名"的一致映射。

    同一个 (类型, 规范化后的值) 永远得到同一个假名：
      - 同一次运行内：靠内存里的 mapping 字典
      - 跨运行：用同一个密钥（HMAC 结果相同），或者用 --map 保存/加载映射表
    """

    def __init__(self, key: bytes, keep_domain: bool = False, keep_private: bool = False):
        self.key = key
        self.keep_domain = keep_domain
        self.keep_private = keep_private
        self.mapping: Dict[str, Dict[str, str]] = {k: {} for k in KINDS}
        self._used: Dict[str, set] = {k: set() for k in KINDS}
        self.custom_kinds: List[str] = []

    # ---- 映射表读写

    def load_mapping(self, data: dict) -> None:
        for kind, table in data.get("mapping", {}).items():
            self.mapping.setdefault(kind, {})
            self._used.setdefault(kind, set())
            for orig, alias in table.items():
                self.mapping[kind][orig] = alias
                self._used[kind].add(alias)

    def dump_mapping(self) -> dict:
        return {
            "version": 1,
            "note": "包含原始敏感值！不要和脱敏日志放在一起分发。",
            "mapping": {k: v for k, v in self.mapping.items() if v},
        }

    # ---- 核心

    def _digest(self, kind: str, value: str, counter: int) -> bytes:
        msg = f"{kind}\x00{value}\x00{counter}".encode("utf-8")
        return hmac.new(self.key, msg, hashlib.sha256).digest()

    def _make(self, kind: str, value: str, d: bytes) -> str:
        if kind == "ipv4":
            if self.keep_private:
                # 内网地址原样保留时，假名不能再用 10.x（会和保留下来的真实内网地址混淆），
                # 改用 198.18.0.0/15（RFC 2544 测试保留段）
                return f"198.{18 + (d[0] & 1)}.{d[1]}.{1 + d[2] % 254}"
            # 映射到 10.0.0.0/8，第四段避开 0 和 255，看起来像普通主机地址
            return f"10.{d[0]}.{d[1]}.{1 + d[2] % 254}"
        if kind == "ipv6":
            groups = [int.from_bytes(d[i:i + 2], "big") for i in range(0, 14, 2)]
            if self.keep_private:
                # 同理改用 2001:db8::/32（文档保留段）
                text = "2001:db8:" + ":".join(f"{g:x}" for g in groups[:6])
            else:
                # 映射到 fd00::/8（ULA，私有地址段），后 120 位来自哈希
                text = f"fd{d[14]:02x}:" + ":".join(f"{g:x}" for g in groups)
            zone = value.partition("%")[2]
            return str(ipaddress.IPv6Address(text)) + ("%" + zone if zone else "")
        if kind == "mac":
            # 02:xx 是"本地管理地址"，不会和真实厂商 OUI 冲突
            return "02:" + ":".join(f"{b:02x}" for b in d[:5])
        if kind == "email":
            local, _, domain = value.partition("@")
            if self.keep_domain:
                new_domain = domain
            else:
                new_domain = self.alias("domain", domain)
            return f"user-{d[:4].hex()}@{new_domain}"
        if kind == "domain":
            # .example 是 RFC 2606 保留的顶级域，永远不会是真实域名
            return f"domain-{d[:3].hex()}.example"
        if kind == "user":
            return f"user-{d[:4].hex()}"
        # 自定义规则：<名字>-<8位十六进制>
        return f"{kind}-{d[:4].hex()}"

    def alias(self, kind: str, value: str) -> str:
        table = self.mapping.setdefault(kind, {})
        used = self._used.setdefault(kind, set())
        if value in table:
            return table[value]
        counter = 0
        while True:
            candidate = self._make(kind, value, self._digest(kind, value, counter))
            # 不同原值撞到同一个假名（IPv4 只有 24 位空间，可能发生）就换个计数器重算，
            # 否则脱敏后两个 IP 会被误当成同一个
            if candidate not in used:
                break
            counter += 1
        table[value] = candidate
        used.add(candidate)
        return candidate

    def ipv4_alias(self, value: str) -> Optional[str]:
        if self.keep_private and is_internal(value):
            return None
        return self.alias("ipv4", value)

    def ipv6_alias(self, value: str) -> Optional[str]:
        if self.keep_private and is_internal(value):
            return None
        return self.alias("ipv6", value)


# ---------------------------------------------------------------- 匹配与替换

Span = Tuple[int, int, str, str]  # (起, 止, 类型, 规范化后的原值)


class Anonymizer:
    def __init__(
        self,
        pseudo: Pseudonymizer,
        kinds: Iterable[str] = KINDS,
        extra_users: Iterable[str] = (),
        custom: Iterable[Tuple[str, "re.Pattern"]] = (),
        learn_users: bool = True,
    ):
        self.p = pseudo
        self.kinds = set(kinds)
        self.learn_users = learn_users
        self.known_users = set(u for u in extra_users if u)
        self.custom = list(custom)
        self.counts: Counter = Counter()
        self.seen: Dict[str, set] = {}
        self._known_re: Optional["re.Pattern"] = None
        self._known_snapshot: frozenset = frozenset()

    # ---- 第一遍：学习用户名

    def learn(self, lines: Iterable[str]) -> None:
        """先把所有上下文里出现过的用户名收集起来，
        第二遍替换时，它们在日志别处"裸着"出现（比如出现在进程命令行里）也能被替换。"""
        if "user" not in self.kinds:
            return
        for line in lines:
            for _, _, _, value in self._user_spans(line):
                self.known_users.add(value)

    def _known_users_re(self) -> Optional["re.Pattern"]:
        names = frozenset(u for u in self.known_users if len(u) >= MIN_LEARNED_USER_LEN)
        if names != self._known_snapshot:
            self._known_snapshot = names
            if names:
                alt = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
                self._known_re = re.compile(rf"(?<![\w.-])(?:{alt})(?![\w-])")
            else:
                self._known_re = None
        return self._known_re

    # ---- 各类识别

    def _user_spans(self, line: str) -> List[Span]:
        out = []
        for rx in USER_CONTEXT_RES:
            for m in rx.finditer(line):
                raw = m.group(1)
                value = _clean_user(raw)
                if value is None:
                    continue
                # 值本身是 IP 或邮箱的话交给对应规则处理
                if EMAIL_RE.fullmatch(value) or IPV4_RE.fullmatch(value) or _valid_ipv6(value):
                    continue
                out.append((m.start(1), m.start(1) + len(value), "user", value))
        return out

    def find_spans(self, line: str) -> List[Span]:
        spans: List[Span] = []
        if "email" in self.kinds:
            for m in EMAIL_RE.finditer(line):
                spans.append((m.start(), m.end(), "email", m.group().lower()))
        if "mac" in self.kinds:
            for m in MAC_RE.finditer(line):
                spans.append((m.start(), m.end(), "mac", m.group().lower().replace("-", ":")))
        if "ipv6" in self.kinds:
            for m in IPV6_CANDIDATE_RE.finditer(line):
                norm = _valid_ipv6(m.group())
                if norm:
                    spans.append((m.start(), m.end(), "ipv6", norm))
        if "ipv4" in self.kinds:
            for m in IPV4_RE.finditer(line):
                spans.append((m.start(), m.end(), "ipv4", m.group()))
        if "user" in self.kinds:
            spans.extend(self._user_spans(line))
            if self.learn_users or self.known_users:
                rx = self._known_users_re()
                if rx:
                    for m in rx.finditer(line):
                        spans.append((m.start(), m.end(), "user", m.group()))
        for name, rx in self.custom:
            for m in rx.finditer(line):
                if m.end() > m.start():
                    g = 1 if rx.groups else 0
                    spans.append((m.start(g), m.end(g), name, m.group(g)))
        return _resolve_overlaps(spans)

    def _alias_for(self, kind: str, value: str) -> Optional[str]:
        if kind == "ipv4":
            return self.p.ipv4_alias(value)
        if kind == "ipv6":
            return self.p.ipv6_alias(value)
        return self.p.alias(kind, value)

    def anonymize_line(self, line: str) -> str:
        spans = self.find_spans(line)
        if not spans:
            return line
        out, pos = [], 0
        for start, end, kind, value in spans:
            alias = self._alias_for(kind, value)
            if alias is None:  # --keep-private 跳过的内网地址
                continue
            out.append(line[pos:start])
            out.append(alias)
            pos = end
            self.counts[kind] += 1
            self.seen.setdefault(kind, set()).add(value)
        out.append(line[pos:])
        return "".join(out)

    def anonymize(self, lines: List[str]) -> List[str]:
        if self.learn_users:
            self.learn(lines)
        return [self.anonymize_line(line) for line in lines]


def _resolve_overlaps(spans: List[Span]) -> List[Span]:
    """多条规则命中同一段文字时（比如邮箱里包含用户名），保留起点最早、最长的那个。"""
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    result: List[Span] = []
    last_end = -1
    for s in spans:
        if s[0] >= last_end:
            result.append(s)
            last_end = s[1]
    return result


# ---------------------------------------------------------------- 还原


def reverse_lines(lines: Iterable[str], mapping: dict) -> List[str]:
    """用映射表把假名换回原值（事件响应时需要定位真实 IP/用户时使用）。"""
    back: Dict[str, str] = {}
    for kind, table in mapping.get("mapping", {}).items():
        if kind == "domain":
            continue  # 域名假名已经包含在邮箱假名里
        for orig, alias in table.items():
            back[alias] = orig
    if not back:
        return list(lines)
    alt = "|".join(re.escape(a) for a in sorted(back, key=len, reverse=True))
    rx = re.compile(rf"(?<![\w.:-])(?:{alt})(?![\w:-]|\.\d)")
    return [rx.sub(lambda m: back[m.group()], line) for line in lines]


# ---------------------------------------------------------------- 命令行


def _parse_custom(specs: List[str]) -> List[Tuple[str, "re.Pattern"]]:
    out = []
    for spec in specs:
        name, sep, pattern = spec.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z][\w-]*", name):
            raise ValueError(f"自定义规则格式应为 名字=正则，例如 order=ORD-\\d+ ，收到: {spec!r}")
        if name in KINDS or name == "domain":
            raise ValueError(f"自定义规则名不能和内置类型重名: {name}")
        try:
            out.append((name, re.compile(pattern)))
        except re.error as e:
            raise ValueError(f"正则写错了 ({name}): {e}")
    return out


def _read_lines(paths: List[str]) -> List[str]:
    lines: List[str] = []
    if not paths or paths == ["-"]:
        return sys.stdin.read().splitlines(keepends=True)
    for p in paths:
        with open(p, "r", encoding="utf-8", errors="surrogateescape") as f:
            lines.extend(f.read().splitlines(keepends=True))
    return lines


def _write_mapping(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # 映射表含原值，只给自己读
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="日志脱敏：把 IP、邮箱、MAC、用户名替换成一致的假名",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 log_anon.py auth.log > auth.anon.log\n"
            "  LOG_ANON_KEY=秘密 python3 log_anon.py a.log b.log -o out.log\n"
            "  python3 log_anon.py auth.log --map map.json -o anon.log\n"
            "  python3 log_anon.py anon.log --reverse --map map.json\n"
        ),
    )
    ap.add_argument("files", nargs="*", help="日志文件（多个文件共享同一套映射；不给或给 - 则读标准输入）")
    ap.add_argument("-o", "--output", help="输出文件（默认标准输出）")
    ap.add_argument("-k", "--key", help=f"HMAC 密钥；相同密钥 → 跨运行假名一致。也可用环境变量 {KEY_ENV}")
    ap.add_argument("-m", "--map", help="映射表 JSON：存在就加载沿用，运行后写回（含原始值，注意保管）")
    ap.add_argument("--reverse", action="store_true", help="用 --map 的映射表把假名还原成原值")
    ap.add_argument("--only", help="只处理这些类型，逗号分隔: " + ",".join(KINDS))
    ap.add_argument("--skip", help="跳过这些类型，逗号分隔")
    ap.add_argument("-u", "--user", action="append", default=[], help="额外指定要替换的用户名（可重复）")
    ap.add_argument("-p", "--pattern", action="append", default=[], metavar="NAME=REGEX",
                    help="自定义规则，例如 -p order='ORD-\\d+'；有捕获组时只替换第 1 组")
    ap.add_argument("--no-learn", action="store_true", help="不在全文里替换已识别出的用户名（只替换有上下文的位置）")
    ap.add_argument("--keep-domain", action="store_true", help="邮箱只换用户部分，保留域名")
    ap.add_argument("--keep-private", action="store_true", help="内网/回环地址（10.x、192.168.x、127.x、fe80:: 等）保持原样")
    ap.add_argument("-q", "--quiet", action="store_true", help="不在 stderr 打印统计")
    return ap


def _kinds_from_args(args) -> List[str]:
    kinds = list(KINDS)
    for opt, keep in ((args.only, True), (args.skip, False)):
        if not opt:
            continue
        chosen = {x.strip() for x in opt.split(",") if x.strip()}
        bad = chosen - set(KINDS)
        if bad:
            raise ValueError(f"未知类型: {', '.join(sorted(bad))}（可选 {', '.join(KINDS)}）")
        kinds = [k for k in kinds if (k in chosen) == keep]
    return kinds


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    err = sys.stderr

    try:
        kinds = _kinds_from_args(args)
        custom = _parse_custom(args.pattern)
    except ValueError as e:
        print(f"错误: {e}", file=err)
        return 2

    mapping_data = None
    if args.map and os.path.exists(args.map):
        try:
            with open(args.map, encoding="utf-8") as f:
                mapping_data = json.load(f)
        except (OSError, ValueError) as e:
            print(f"错误: 映射表读取失败 {args.map}: {e}", file=err)
            return 2

    try:
        lines = _read_lines(args.files)
    except OSError as e:
        print(f"错误: {e}", file=err)
        return 2

    if args.reverse:
        if not mapping_data:
            print("错误: --reverse 需要用 --map 指定一个已存在的映射表", file=err)
            return 2
        result = reverse_lines(lines, mapping_data)
    else:
        key_str = args.key or os.environ.get(KEY_ENV)
        if key_str:
            key = key_str.encode("utf-8")
        else:
            key = secrets.token_bytes(32)
            if not args.quiet and not mapping_data:
                hint = "（已用 --map 保存映射）" if args.map else f"；要跨运行一致请用 --key / {KEY_ENV} 或 --map"
                print(f"提示: 未提供密钥，本次使用随机密钥：本次运行内一致{hint}", file=err)

        pseudo = Pseudonymizer(key, keep_domain=args.keep_domain, keep_private=args.keep_private)
        if mapping_data:
            pseudo.load_mapping(mapping_data)
        anon = Anonymizer(pseudo, kinds=kinds, extra_users=args.user, custom=custom,
                          learn_users=not args.no_learn)
        result = anon.anonymize(lines)

        if args.map:
            try:
                _write_mapping(args.map, pseudo.dump_mapping())
            except OSError as e:
                print(f"错误: 映射表写入失败 {args.map}: {e}", file=err)
                return 2

        if not args.quiet:
            distinct = {k: len(v) for k, v in anon.seen.items()}
            parts = []
            for kind in list(KINDS) + [n for n, _ in custom]:
                if anon.counts[kind]:
                    label = KIND_LABELS.get(kind, kind)
                    parts.append(f"{label} {anon.counts[kind]} 处/{distinct.get(kind, 0)} 个")
            summary = "，".join(parts) if parts else "没有找到需要替换的内容"
            print(f"脱敏完成: {len(lines)} 行；{summary}", file=err)

    text = "".join(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
