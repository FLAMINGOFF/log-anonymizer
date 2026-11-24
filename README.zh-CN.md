# 日志脱敏工具（Log Anonymizer）

[English](README.md) | **简体中文**

一个很小的 Python 命令行工具：把日志里的 **IP 地址（IPv4/IPv6）、邮箱、MAC 地址、用户名**
替换成**一致的假名**：同一个值永远变成同一个假名。脱敏后的日志依然能分析
（"爆破 SSH 的那个 IP 后来登录成功了"这种关联不会丢），又可以放心贴到工单、论坛或者发给 AI。

```
203.0.113.7  → 10.179.186.91      （每次出现都一样）
alice        → user-a67b130b
bob@example.com → user-f31c090d@domain-55465f.example
```

只用 Python 标准库，不需要 `pip install`。Python 3.8+。

## 怎么用

```bash
python3 log_anon.py auth.log > auth.anon.log           # 随机密钥：本次运行内一致
python3 log_anon.py a.log b.log -o out.log             # 多个文件共用一套映射
cat auth.log | python3 log_anon.py                     # 也可以读标准输入
LOG_ANON_KEY='长一点的密钥' python3 log_anon.py auth.log  # 同一个密钥 → 跨运行假名一致
python3 log_anon.py auth.log -k '长一点的密钥'           # （或直接传密钥）
python3 log_anon.py auth.log --map map.json -o anon.log   # 保存/沿用映射表
python3 log_anon.py anon.log --reverse --map map.json  # 把假名还原成原值

python3 log_anon.py auth.log --only ipv4,ipv6          # 只处理部分类型：email,ipv4,ipv6,mac,user
python3 log_anon.py auth.log --skip mac
python3 log_anon.py auth.log --keep-private            # 10.x / 192.168.x / 127.x / fe80:: 保持原样
python3 log_anon.py auth.log --keep-domain             # bob@corp.com → user-xxxx@corp.com
python3 log_anon.py auth.log -u mallory                # 额外指定用户名
python3 log_anon.py app.log -p 'order=order_id=(\d+)'  # 自定义规则 名字=正则（有捕获组只替换第 1 组）

python3 -m unittest -v                                 # 离线测试
```

用 [`examples/auth.log`](examples/auth.log) 试一下（统计信息打印在 stderr）：

```
$ python3 log_anon.py examples/auth.log -k demo
脱敏完成: 11 行；邮箱 2 处/2 个，IPv4 7 处/4 个，IPv6 1 处/1 个，MAC 1 处/1 个，用户名 12 处/4 个
... sshd[2211]: Invalid user user-d85fc666 from 10.179.186.91 port 51022
... sshd[2215]: Failed password for user-ba5e85f3 from 10.179.186.91 port 51040 ssh2
... sshd[3102]: Accepted publickey for user-a67b130b from 10.41.245.55 port 60112 ssh2
... sudo:    user-a67b130b : TTY=pts/0 ; PWD=/home/user-a67b130b ; USER=user-ba5e85f3 ; ...
... app[911]: login ok user=user-f31c090d@domain-55465f.example ip=fdb8:6d6d:644:c0ee:4d2d:1977:338a:3862 mac=02:5e:44:02:ab:62
... cron[1200]: (user-a67b130b) CMD (/home/user-a67b130b/backup.sh --to 10.134.222.244)
... app[911]: version 1.2.3.4.5 build 2026.11.23 started at 08:41:00      ← 不会误伤
```

退出码：成功 `0`，参数错误或文件读不了 `2`。

## 原理

```
读入所有行
   │
   ├─ 第一遍：从上下文学习用户名（sshd/sudo/pam 固定句式、user=…、/home/<名字>）
   │
   └─ 第二遍，逐行：
        各识别器 → 片段 (起, 止, 类型, 规范化后的值)
          邮箱 · MAC · IPv6 · IPv4 · 上下文用户名 · 学到的用户名 · 自定义规则
        片段重叠时：起点最早、再按最长的胜出（邮箱优先于其中的用户名）
        每个片段 → 假名 = mapping[类型][值]
                          没有就推导：HMAC-SHA256(密钥, 类型 ‖ 值 ‖ 计数器)
```

**为什么用 HMAC 而不是直接哈希？** IPv4 一共只有 2³² 个。如果假名是 `sha256(ip)`，
任何人花几分钟把 40 亿个地址全哈希一遍，就能把所有假名反查回去。加了密钥之后，
只有持有密钥的人才能重算映射。不给密钥时工具会用随机密钥：本次运行内一致，
但不同次运行之间无法关联。

**假名保留原来的格式**，日志解析器、`grep`、仪表盘照样能用：

| 类型 | 假名 | 为什么选这个范围 |
|---|---|---|
| IPv4 | `10.x.y.z`（第四段 1–254） | 私有地址段，不会路由到真实主机 |
| IPv6 | `fdXX:…` | ULA（`fc00::/7`），私有 |
| 加了 `--keep-private` 的 IPv4/IPv6 | `198.18.0.0/15` / `2001:db8::/32` | 避免假名和保留下来的真实内网地址混淆 |
| MAC | `02:xx:xx:xx:xx:xx` | 置位"本地管理"位，不对应任何真实厂商 |
| 邮箱 | `user-<8位十六进制>@domain-<6位十六进制>.example` | `.example` 是保留域名（RFC 2606）；同一域名始终得到同一个假名 |
| 用户名 | `user-<8位十六进制>` | |
| 自定义规则 | `<名字>-<8位十六进制>` | |

**碰撞处理：** IPv4 假名空间只有 24 位，两个不同 IP 可能撞到同一个假名，
那样两个攻击者就会被悄悄合并成一个。工具记录已用的假名，撞了就把计数器加一重新推导。

**规范化：** `2001:0DB8::01F4` 和 `2001:db8::1f4` 是同一个地址，`Bob@Example.com` 和
`bob@example.com` 是同一个邮箱，`00-1A-2B-…` 和 `00:1a:2b:…` 是同一个 MAC。
查表前先规范化，所以得到同一个假名。

**用户名**没有固定格式，只能靠上下文识别：
`Invalid user X`、`Failed password for [invalid user] X from`、`authenticating user X`、
`session opened for user X`、`sudo: X :`、`user=` / `username:` / `"login":"X"` / `account=`，
以及家目录路径 `/home/X`、`/Users/X`、`C:\Users\X`。纯数字（`uid=1000`）和 `unknown`、`-`、
`none` 这类词会跳过。这样学到的用户名，在日志里任何地方作为整词出现也会被替换
（比如 `cron: (alice) CMD`），除非加 `--no-learn`。短于 3 个字符的用户名不做全文替换，
免得误伤普通单词。

**IP 识别：** IPv4 要求四段都 ≤ 255，而且不会从 `1.2.3.4.5` 这种更长的点分数字里截一段出来。
IPv6 先宽松地找候选，再用 `ipaddress` 校验，所以 `12:34:56` 这样的时间戳和 MAC 地址
不会被当成 IPv6。`::ffff:192.0.2.1` 整体按一个 IPv6 处理。

## 映射表（`--map`）

```json
{ "mapping": { "ipv4": { "203.0.113.7": "10.179.186.91" }, "user": { "alice": "user-a67b130b" } }, ... }
```

- 文件存在就先加载，所以即使不给密钥，跨运行、跨几个月的日志假名也保持一致。
  新出现的值追加进去，运行完写回。
- `--reverse --map map.json` 把假名换回原值：应急响应时先分享脱敏日志，之后需要查某一行的真实 IP 时用。
- **映射表里是原始敏感值。** 文件权限是 `0600`，千万不要和脱敏日志一起发出去。

## 局限

- **脱敏 ≠ 匿名。** 上下文照样会泄露身份：主机名、URL、查询参数、会话 ID、时间戳、
  少见的 User-Agent。默认不处理的：邮箱之外的主机名/域名、手机号、银行卡号、API 密钥
  （可以用 [secret-scanner](https://github.com/FLAMINGOFF/secret-scanner)）。
  针对你的日志格式用 `-p` 加规则。
- 用户名只能靠上面那些模式识别。从没在可识别的上下文里出现过（也没用 `-u` 指定）的用户名会保持明文。
  输出一定要人工过一遍。
- 学到 `root`、`admin` 这样的用户名后会在全文按整词替换，包括 `/root/` 这样的路径。
  这是"多脱敏"，属于安全的方向。
- 不保留前缀：`203.0.113.7` 和 `203.0.113.8` 得到毫无关系的假名，看不出它们在同一个网段。
  Crypto-PAn 之类的工具能保留前缀，代价是泄露网络结构。
- 同一个人的邮箱前缀和用户名会得到不同的假名（`carol` 和 `carol@corp.example.org`），
  因为工具无法知道它们属于同一个人。
- `--reverse` 还原的是规范化后的值（邮箱/MAC 小写、IPv6 压缩写法），不一定是原始的大小写写法。
- 文件会整个读进内存（要扫两遍）。普通日志没问题；几个 GB 的文件请先切分，共用一个 `--map`。

## 现实中的同类工具

Logstash 的 [`fingerprint` 过滤器](https://www.elastic.co/guide/en/logstash/current/plugins-filters-fingerprint.html)
（在管道里用带密钥的哈希生成假名）、[Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn)
（保留前缀的 IP 匿名化）、[Microsoft Presidio](https://github.com/microsoft/presidio)
（用 NLP 识别个人信息），以及给抓包文件脱敏的 `tcprewrite`。
