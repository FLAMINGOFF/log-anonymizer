# Log Anonymizer

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that replaces **IP addresses (IPv4/IPv6), email addresses, MAC addresses
and usernames** in log files with **consistent pseudonyms**: the same value always becomes
the same alias, so the anonymized log is still useful for analysis ("the IP that brute-forced
SSH is the one that later logged in") but safe to paste into a ticket, a forum post, or an LLM.

```
203.0.113.7  → 10.179.186.91      (every time it appears)
alice        → user-a67b130b
bob@example.com → user-f31c090d@domain-55465f.example
```

Standard library only: no `pip install`. Python 3.8+.

## Usage

```bash
python3 log_anon.py auth.log > auth.anon.log           # random key: consistent within this run
python3 log_anon.py a.log b.log -o out.log             # several files share one mapping
cat auth.log | python3 log_anon.py                     # stdin works too
LOG_ANON_KEY='long secret' python3 log_anon.py auth.log   # same key → same aliases across runs
python3 log_anon.py auth.log -k 'long secret'          # (or pass the key directly)
python3 log_anon.py auth.log --map map.json -o anon.log   # save/reuse the mapping table
python3 log_anon.py anon.log --reverse --map map.json  # turn aliases back into real values

python3 log_anon.py auth.log --only ipv4,ipv6          # only some kinds: email,ipv4,ipv6,mac,user
python3 log_anon.py auth.log --skip mac
python3 log_anon.py auth.log --keep-private            # leave 10.x / 192.168.x / 127.x / fe80:: alone
python3 log_anon.py auth.log --keep-domain             # bob@corp.com → user-xxxx@corp.com
python3 log_anon.py auth.log -u mallory                # force extra usernames
python3 log_anon.py app.log -p 'order=order_id=(\d+)'  # custom rule NAME=REGEX (group 1 if present)

python3 -m unittest -v                                 # offline tests
```

Example with [`examples/auth.log`](examples/auth.log) (the summary on stderr is in Chinese:
`处` = occurrences, `个` = distinct values):

```
$ python3 log_anon.py examples/auth.log -k demo
脱敏完成: 11 行；邮箱 2 处/2 个，IPv4 7 处/4 个，IPv6 1 处/1 个，MAC 1 处/1 个，用户名 12 处/4 个
... sshd[2211]: Invalid user user-d85fc666 from 10.179.186.91 port 51022
... sshd[2215]: Failed password for user-ba5e85f3 from 10.179.186.91 port 51040 ssh2
... sshd[3102]: Accepted publickey for user-a67b130b from 10.41.245.55 port 60112 ssh2
... sudo:    user-a67b130b : TTY=pts/0 ; PWD=/home/user-a67b130b ; USER=user-ba5e85f3 ; ...
... app[911]: login ok user=user-f31c090d@domain-55465f.example ip=fdb8:6d6d:644:c0ee:4d2d:1977:338a:3862 mac=02:5e:44:02:ab:62
... cron[1200]: (user-a67b130b) CMD (/home/user-a67b130b/backup.sh --to 10.134.222.244)
... app[911]: version 1.2.3.4.5 build 2026.11.23 started at 08:41:00      ← untouched
```

Exit code `0` on success, `2` for bad arguments or unreadable files.

## How it works

```
read all lines
   │
   ├─ pass 1: learn usernames from context (sshd/sudo/pam phrases, user=…, /home/<name>)
   │
   └─ pass 2, per line:
        detectors → spans (start, end, kind, normalized value)
          email · MAC · IPv6 · IPv4 · contextual usernames · learned usernames · custom rules
        overlaps resolved: earliest start, then longest wins (email beats the user inside it)
        each span → alias = mapping[kind][value]
                             or derive it: HMAC-SHA256(key, kind ‖ value ‖ counter)
```

**Why HMAC and not a plain hash?** IPv4 has only 2³² values. If aliases were `sha256(ip)`,
anyone could hash all 4 billion addresses in minutes and reverse every alias. With a secret
key, only the key holder can recompute the mapping. With no key the tool uses a random one,
so aliases are consistent within a run but can't be linked across runs.

**Aliases keep the format** so log parsers, `grep` and dashboards still work:

| Kind | Alias | Why this range |
|---|---|---|
| IPv4 | `10.x.y.z` (last octet 1–254) | private range, never routable |
| IPv6 | `fdXX:…` | ULA (`fc00::/7`), private |
| IPv4/IPv6 with `--keep-private` | `198.18.0.0/15` / `2001:db8::/32` | so aliases can't be confused with the real private addresses that were kept |
| MAC | `02:xx:xx:xx:xx:xx` | locally administered bit set, no real vendor OUI |
| Email | `user-<8 hex>@domain-<6 hex>.example` | `.example` is reserved (RFC 2606); the same domain always gets the same alias |
| Username | `user-<8 hex>` | |
| Custom rule | `<name>-<8 hex>` | |

**Collisions:** the IPv4 alias space is only 24 bits, so two different IPs could land on
the same alias, which would silently merge two attackers into one. The tool tracks used
aliases and re-derives with an incremented counter when that happens.

**Normalization:** `2001:0DB8::01F4` and `2001:db8::1f4` are the same address, `Bob@Example.com`
and `bob@example.com` the same mailbox, `00-1A-2B-…` and `00:1a:2b:…` the same MAC. Values
are normalized before lookup, so they get the same alias.

**Usernames** have no fixed format, so they are found by context:
`Invalid user X`, `Failed password for [invalid user] X from`, `authenticating user X`,
`session opened for user X`, `sudo: X :`, `user=` / `username:` / `"login":"X"` / `account=`,
and home paths `/home/X`, `/Users/X`, `C:\Users\X`. Pure numbers (`uid=1000`) and words like
`unknown`, `-`, `none` are skipped. Every username learned this way is then also replaced
wherever it appears as a whole word (for example `cron: (alice) CMD`), unless you pass
`--no-learn`. Names shorter than 3 characters are not replaced globally to avoid wrecking
ordinary words.

**IP detection:** IPv4 requires four octets ≤ 255 and refuses to cut a piece out of longer
dotted numbers like `1.2.3.4.5`. IPv6 candidates are found loosely, then validated with
`ipaddress`, so timestamps like `12:34:56` and MAC addresses are not mistaken for IPv6.
`::ffff:192.0.2.1` is treated as one IPv6 address.

## The mapping file (`--map`)

```json
{ "mapping": { "ipv4": { "203.0.113.7": "10.179.186.91" }, "user": { "alice": "user-a67b130b" } }, ... }
```

- If the file exists it is loaded first, so aliases stay the same across runs and across
  months of logs, even without a key. New values are appended and the file is written back.
- `--reverse --map map.json` replaces aliases with the original values, useful during incident
  response when you share the anonymized log and later need the real IP of one line.
- **The mapping file contains the original sensitive values.** It is written with mode `0600`.
  Never ship it together with the anonymized logs.

## Limitations

- **Anonymization ≠ anonymity.** Context still leaks: hostnames, URLs, query strings, session
  IDs, timestamps and unusual user agents can identify people. Not covered by default:
  hostnames/domains outside emails, phone numbers, credit cards, API keys (see
  [secret-scanner](https://github.com/FLAMINGOFF/secret-scanner)). Add `-p` rules for your format.
- Usernames are only found by the patterns above. A username that never appears in a
  recognized context (and isn't passed with `-u`) stays in clear text. Always review the output.
- Learned usernames like `root` or `admin` are replaced everywhere as whole words, including
  in paths such as `/root/`. That over-anonymizes, which is the safe direction.
- Not prefix-preserving: `203.0.113.7` and `203.0.113.8` get unrelated aliases, so you can't
  tell they share a subnet. Tools like Crypto-PAn keep prefixes, at the cost of leaking structure.
- An email's local part and the same person's username get different aliases (`carol` vs
  `carol@corp.example.org`), because the tool can't know they belong together.
- `--reverse` restores the normalized value (lowercased email/MAC, compressed IPv6), not
  necessarily the exact original spelling.
- Files are read fully into memory (two passes). Fine for normal logs; for multi-GB files,
  split them and share one `--map`.

## Real-world equivalents

Logstash's [`fingerprint` filter](https://www.elastic.co/guide/en/logstash/current/plugins-filters-fingerprint.html)
(keyed-hash pseudonyms in a pipeline), [Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn)
(prefix-preserving IP anonymization), [Microsoft Presidio](https://github.com/microsoft/presidio)
(PII detection with NLP), and `tcprewrite` for anonymizing packet captures.
