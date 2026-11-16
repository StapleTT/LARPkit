# larpkit

A small, dependency-light toolkit for **authorized** layer-2 / LAN testing. Two scripts:

| Script | What it does |
|---|---|
| `larp-scan.sh` | Discover live hosts on the local subnet (excluding the gateway and this machine by default). |
| `larp-blackhole.sh` | Reversibly cut named hosts (or every discovered host) off the network via a **scoped ARP blackhole** — their traffic to/from the gateway is poisoned to a bogus, unused MAC and silently dropped. |

> [!WARNING]
> **Authorized testing only, on a network you own or have explicit written permission to test.**
> ARP poisoning disrupts other people's connectivity and is illegal on networks
> you don't control. All effects are reversible — caches are restored on exit —
> but use this only in a lab or a sanctioned engagement.

---

## Requirements

- **bash** 4+ and **iproute2** (`ip`, and `ss` for SSH-session detection)
- **python3** (standard library only) — used by `larp-blackhole.sh` for the raw ARP socket
- **nmap** — required by `larp-scan.sh`, and by `larp-blackhole.sh --all`
- **root** (`sudo`) — required by `larp-blackhole.sh`; recommended for `larp-scan.sh` (enables ARP discovery)

---

## `larp-scan.sh`

List live hosts on your network. Prints the result to **stdout**; status/spinner go to stderr, so it composes cleanly in pipelines.

```
larp-scan.sh [options]
```

| Option | Description |
|---|---|
| `-i, --iface IFACE` | interface to use (default: default route) |
| `-s, --subnet CIDR` | subnet to scan (default: from interface) |
| `-x, --exclude IP` | extra IP to exclude (repeatable) |
| `-g, --keep-gateway` | include the gateway in results |
| `-m, --keep-me` | include this machine in results |
| `-d, --delim STR` | output separator (default: space) |
| `-l, --lines` | one IP per line |
| `-q, --quiet` | only print the result |
| `-h, --help` / `-V, --version` | help / version |

**Examples**

```sh
sudo ./larp-scan.sh                              # live hosts on the local subnet
./larp-scan.sh -s 10.0.0.0/24 -x 10.0.0.50 -d ,  # custom subnet, extra exclude, CSV
./larp-scan.sh -q -l | xargs -I{} ping -c1 {}    # feed results into another tool
```

---

## `larp-blackhole.sh`

Poisons the ARP caches of each target **and** the gateway so traffic between them
is sent to a bogus MAC (`02:00:00:00:00:fe`) and dropped. Only the hosts you list
are touched (or, with `--all`, every discovered host minus the exclusions). Press
**Ctrl+C** to stop; all affected caches are restored on exit.

```
sudo larp-blackhole.sh [options] <target_ip> [<target_ip> ...]
sudo larp-blackhole.sh [options] --all
```

| Option | Description |
|---|---|
| `-g, --gateway IP` | gateway to blackhole through (default: from route) |
| `-i, --iface IFACE` | interface to use (default: from route) |
| `-t, --interval SEC` | seconds between poison bursts (default: 1.5) |
| `-A, --all` | discover and target every live host on the subnet, excluding the gateway, this machine, and any host with an active SSH session |
| `--keep-ssh` | with `--all`, do **not** exclude SSH-session hosts |
| `-T, --track` | watch for hosts that change IP to dodge targeting (on by default with `--all`; works for named targets too) |
| `--no-track` | disable IP-change (evasion) detection |
| `-h, --help` / `-V, --version` | help / version |

**Examples**

```sh
sudo ./larp-blackhole.sh 172.16.0.61                     # one host
sudo ./larp-blackhole.sh 172.16.0.61 172.16.0.62         # several hosts
sudo ./larp-blackhole.sh -g 172.16.0.1 -t 2 172.16.0.61  # explicit gateway, 2s interval
sudo ./larp-blackhole.sh --all                           # every host on the subnet
sudo ./larp-blackhole.sh --track 172.16.0.61 172.16.0.62 # named targets + evasion watch
```

### Safety behavior

- **Reversible:** on Ctrl+C (or `SIGTERM`) the correct ARP mappings are re-broadcast; targets recover within a few seconds.
- **Scoped:** with explicit targets, nothing outside your list is touched.
- **`--all` auto-excludes** the gateway, this machine, and hosts holding a live SSH session (so you don't knock over your own admin sessions). Override SSH exclusion with `--keep-ssh`.

### IP-change (evasion) detection

With tracking enabled, each host is remembered by **MAC address** across runs. If a
known MAC reappears at a *different* IP — the fingerprint of someone changing their
IP to slip off the list — it's flagged and the new IP is re-targeted (unless that IP
is itself excluded).

- Baseline is stored at `/var/lib/larpkit/known-hosts.map` (override with the `LARPKIT_STATE_DIR` env var).
- `--all` inspects the whole segment; named targets are watched individually.
- **Limitation:** detection is MAC-based, so a host that spoofs its MAC *and* changes IP looks brand-new and can't be correlated. For named targets, a moved host can only be re-found if its new IP is already in the neighbor table — use `--all` for reliable re-discovery.

---

## Notes

- IPv4 / ARP only (IPv6 uses NDP and is out of scope).
- `larp-blackhole.sh` is self-contained — it inlines the discovery logic, so it does not call `larp-scan.sh` at runtime.
