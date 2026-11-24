"""离线测试：python3 -m unittest -v"""

import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import log_anon
from log_anon import Anonymizer, Pseudonymizer, reverse_lines

KEY = b"test-key"


def anon(text, **kw):
    pseudo_kw = {k: kw.pop(k) for k in ("keep_domain", "keep_private") if k in kw}
    a = Anonymizer(Pseudonymizer(KEY, **pseudo_kw), **kw)
    out = a.anonymize(text.splitlines(keepends=True))
    return "".join(out), a


class TestDetection(unittest.TestCase):
    def test_ipv4_replaced_and_consistent(self):
        out, a = anon("a 203.0.113.7 b 203.0.113.7 c 198.51.100.1\n")
        self.assertNotIn("203.0.113.7", out)
        ips = re.findall(r"10\.\d+\.\d+\.\d+", out)
        self.assertEqual(len(ips), 3)
        self.assertEqual(ips[0], ips[1])
        self.assertNotEqual(ips[0], ips[2])
        self.assertEqual(a.counts["ipv4"], 3)

    def test_ipv4_not_version_or_invalid(self):
        line = "version 1.2.3.4.5 build 2026.11.23 bad 999.1.1.1 at 12:34:56\n"
        out, _ = anon(line)
        self.assertEqual(out, line)

    def test_ipv4_end_of_sentence(self):
        out, _ = anon("connect from 8.8.8.8.\n")
        self.assertNotIn("8.8.8.8", out)
        self.assertTrue(out.rstrip().endswith("."))

    def test_ipv6(self):
        out, a = anon("from 2001:db8::1f4 and 2001:0DB8:0:0:0:0:0:1F4 and ::1\n")
        self.assertNotIn("2001:db8", out.lower())
        aliases = re.findall(r"fd[0-9a-f:]+", out)
        # 两种写法是同一个地址，规范化后应得到同一个假名
        self.assertEqual(aliases[0], aliases[1])
        self.assertEqual(a.counts["ipv6"], 3)

    def test_ipv6_ignores_timestamps_and_mac(self):
        line = "at 12:34:56 dev 00:1a:2b:3c:4d:5e\n"
        out, a = anon(line, kinds=["ipv6"])
        self.assertEqual(out, line)

    def test_ipv4_mapped_ipv6_is_one_span(self):
        out, a = anon("peer ::ffff:192.0.2.1 ok\n")
        self.assertEqual(a.counts["ipv6"], 1)
        self.assertEqual(a.counts["ipv4"], 0)
        self.assertNotIn("192.0.2.1", out)

    def test_email_case_insensitive_and_domain_hidden(self):
        out, a = anon("Bob@Example.com bob@example.com\n")
        first, second = out.split()
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(".example"))
        self.assertNotIn("Example.com", out)

    def test_keep_domain(self):
        out, _ = anon("to bob@example.com\n", keep_domain=True)
        self.assertRegex(out, r"user-[0-9a-f]{8}@example\.com")

    def test_same_domain_same_alias(self):
        out, _ = anon("a@corp.test b@corp.test\n")
        doms = [x.split("@")[1] for x in out.split()]
        self.assertEqual(doms[0], doms[1])

    def test_mac(self):
        out, a = anon("mac=00:1A:2B:3C:4D:5E other=00-1a-2b-3c-4d-5e\n")
        macs = re.findall(r"02(?::[0-9a-f]{2}){5}", out)
        self.assertEqual(len(macs), 2)
        self.assertEqual(macs[0], macs[1])

    def test_ssh_usernames(self):
        log = (
            "sshd: Invalid user admin from 203.0.113.7 port 1\n"
            "sshd: Failed password for invalid user admin from 203.0.113.7 port 1 ssh2\n"
            "sshd: Failed password for root from 203.0.113.7 port 2 ssh2\n"
            "sshd: Accepted publickey for alice from 198.51.100.2 port 3 ssh2\n"
            "pam_unix: session opened for user alice(uid=1001) by (uid=0)\n"
            "sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls\n"
            "Connection closed by authenticating user root 203.0.113.7 port 9 [preauth]\n"
        )
        out, a = anon(log)
        for name in ("admin", "alice", "root"):
            self.assertIsNone(re.search(rf"\b{name}\b", out), f"{name} 没被替换: {out}")
        self.assertIn("(uid=1001)", out)  # uid 数字不当用户名

    def test_key_value_and_json_users(self):
        out, _ = anon('user=dave username: erin {"login":"frank"} owner=-\n')
        for name in ("dave", "erin", "frank"):
            self.assertNotIn(name, out)
        self.assertIn("owner=-", out)

    def test_home_paths(self):
        out, _ = anon("open /home/grace/.ssh/id_rsa and /Users/heidi/x and C:\\Users\\ivan\\y\n")
        for name in ("grace", "heidi", "ivan"):
            self.assertNotIn(name, out)
        self.assertIn("/.ssh/id_rsa", out)

    def test_learned_user_replaced_everywhere(self):
        log = "sshd: Accepted password for judy from 1.1.1.1 port 1\ncron: (judy) CMD (backup)\n"
        out, _ = anon(log)
        self.assertNotIn("judy", out)
        out2, _ = anon(log, learn_users=False)
        self.assertIn("(judy)", out2)

    def test_short_learned_user_not_global(self):
        out, _ = anon("user=al\nalpha al beta\n")
        self.assertIn("al beta", out)  # 太短的用户名不做全文替换，避免误伤

    def test_extra_user(self):
        out, _ = anon("backup by mallory done\n", extra_users=["mallory"])
        self.assertNotIn("mallory", out)

    def test_email_wins_over_user(self):
        out, a = anon("user=bob@example.com\n")
        self.assertEqual(a.counts["email"], 1)
        self.assertEqual(a.counts["user"], 0)

    def test_kinds_filter(self):
        line = "user=bob ip=203.0.113.7\n"
        out, _ = anon(line, kinds=["ipv4"])
        self.assertIn("user=bob", out)
        self.assertNotIn("203.0.113.7", out)

    def test_keep_private(self):
        out, _ = anon("10.0.0.5 192.168.1.1 127.0.0.1 fe80::1 203.0.113.7\n", keep_private=True)
        for kept in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "fe80::1"):
            self.assertIn(kept, out)
        self.assertNotIn("203.0.113.7", out)
        # 假名不能落在内网段，否则会和保留下来的真实内网地址混淆
        self.assertRegex(out, r"198\.1[89]\.\d+\.\d+\n$")

    def test_keep_private_ipv6_alias_not_internal(self):
        out, _ = anon("from 2a00:1450::1\n", keep_private=True)
        self.assertIn("2001:db8:", out)

    def test_custom_pattern(self):
        rx = [("order", re.compile(r"order_id=(\d+)"))]
        out, a = anon("order_id=12345 then order_id=12345\n", custom=rx)
        self.assertNotIn("12345", out)
        self.assertEqual(out.count("order_id=order-"), 2)


class TestPseudonymizer(unittest.TestCase):
    def test_same_key_same_alias(self):
        a = Pseudonymizer(b"k").alias("ipv4", "203.0.113.7")
        b = Pseudonymizer(b"k").alias("ipv4", "203.0.113.7")
        c = Pseudonymizer(b"other").alias("ipv4", "203.0.113.7")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_alias_formats_are_valid(self):
        import ipaddress
        p = Pseudonymizer(KEY)
        ipaddress.IPv4Address(p.alias("ipv4", "1.2.3.4"))
        self.assertTrue(ipaddress.IPv6Address(p.alias("ipv6", "2001:db8::1")).is_private)
        self.assertTrue(p.alias("ipv4", "8.8.8.8").startswith("10."))

    def test_collision_rehash(self):
        p = Pseudonymizer(KEY)
        first = p.alias("ipv4", "1.1.1.1")
        # 人为让下一个值的第一个候选撞上 first
        orig = p._make
        calls = {"n": 0}

        def fake(kind, value, d):
            calls["n"] += 1
            return first if calls["n"] == 1 else orig(kind, value, d)

        p._make = fake
        second = p.alias("ipv4", "2.2.2.2")
        self.assertNotEqual(first, second)

    def test_mapping_roundtrip(self):
        p = Pseudonymizer(KEY)
        alias = p.alias("user", "alice")
        q = Pseudonymizer(b"completely different key")
        q.load_mapping(json.loads(json.dumps(p.dump_mapping())))
        self.assertEqual(q.alias("user", "alice"), alias)


class TestReverse(unittest.TestCase):
    def test_reverse(self):
        log = "Failed password for root from 203.0.113.7 port 1; mail bob@example.com\n"
        pseudo = Pseudonymizer(KEY)
        out = Anonymizer(pseudo).anonymize([log])
        self.assertNotEqual(out[0], log)
        back = reverse_lines(out, pseudo.dump_mapping())
        self.assertEqual(back[0], log)


class TestCLI(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = log_anon.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_cli_map_and_reverse(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "a.log")
            mp = os.path.join(d, "map.json")
            anon_path = os.path.join(d, "anon.log")
            with open(src, "w") as f:
                f.write("Accepted password for alice from 203.0.113.7 port 22\n")
            code, _, err = self.run_cli(src, "--map", mp, "-o", anon_path)
            self.assertEqual(code, 0)
            self.assertIn("脱敏完成", err)
            self.assertEqual(os.stat(mp).st_mode & 0o777, 0o600)
            with open(anon_path) as f:
                anon_text = f.read()
            self.assertNotIn("alice", anon_text)

            # 第二次运行（随机密钥不同）也沿用映射表 → 结果一致
            code, out2, _ = self.run_cli(src, "--map", mp, "-q")
            self.assertEqual(out2, anon_text)

            code, back, _ = self.run_cli(anon_path, "--reverse", "--map", mp)
            with open(src) as f:
                self.assertEqual(back, f.read())

    def test_cli_key_consistent(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "a.log")
            with open(src, "w") as f:
                f.write("ip 203.0.113.7\n")
            _, o1, _ = self.run_cli(src, "-k", "s3cret", "-q")
            _, o2, _ = self.run_cli(src, "-k", "s3cret", "-q")
            self.assertEqual(o1, o2)

    def test_cli_errors(self):
        self.assertEqual(self.run_cli("--only", "nope")[0], 2)
        self.assertEqual(self.run_cli("-p", "bad")[0], 2)
        self.assertEqual(self.run_cli("-p", "ipv4=x")[0], 2)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_cli(os.path.join(d, "x"), "--reverse")[0], 2)
            self.assertEqual(self.run_cli(os.path.join(d, "missing.log"))[0], 2)


if __name__ == "__main__":
    unittest.main()
