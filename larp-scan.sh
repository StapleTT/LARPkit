#!/usr/bin/env bash
# larp-scan.sh - list live hosts on the local network (excluding gateway + self)
set -uo pipefail

VERSION="1.1.0"
PROG=${0##*/}

# ---------- styling (only when stderr is a terminal) ----------
if [[ -t 2 && -z ${NO_COLOR:-} ]]; then
  B=$'\e[1m' D=$'\e[2m' R=$'\e[0m'
  RED=$'\e[31m' GRN=$'\e[32m' YEL=$'\e[33m' CYN=$'\e[36m'
else
  B= D= R= RED= GRN= YEL= CYN=
fi

info() { (( QUIET )) || printf '%s::%s %s\n' "$CYN" "$R" "$*" >&2; }
warn() { (( QUIET )) || printf '%s!!%s %s\n' "$YEL" "$R" "$*" >&2; }
die()  { printf '%sxx%s %s\n' "$RED" "$R" "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
${B}${PROG}${R} ${D}v${VERSION}${R} - list live hosts on your network

${B}USAGE${R}
  ${PROG} [options]

${B}OPTIONS${R}
  -i, --iface IFACE     interface to use        ${D}(default: default route)${R}
  -s, --subnet CIDR     subnet to scan          ${D}(default: from interface)${R}
  -x, --exclude IP      extra IP to exclude     ${D}(repeatable)${R}
  -g, --keep-gateway    include the gateway
  -m, --keep-me         include this machine
  -d, --delim STR       output separator        ${D}(default: " ")${R}
  -l, --lines           one IP per line
  -q, --quiet           only print the result
  -h, --help            show this help
  -V, --version         show version

${B}EXAMPLES${R}
  sudo ${PROG}
  ${PROG} -s 10.0.0.0/24 -x 10.0.0.50 -d ,
  ${PROG} -q -l | xargs -I{} ping -c1 {}
USAGE
}

# ---------- args ----------
IFACE= SUBNET= DELIM=' ' QUIET=0 KEEP_GW=0 KEEP_ME=0 EXCLUDES=()
while (( $# )); do
  case $1 in
    -i|--iface)        IFACE=${2:?missing interface}; shift ;;
    -s|--subnet)       SUBNET=${2:?missing subnet}; shift ;;
    -x|--exclude)      EXCLUDES+=("${2:?missing IP}"); shift ;;
    -g|--keep-gateway) KEEP_GW=1 ;;
    -m|--keep-me)      KEEP_ME=1 ;;
    -d|--delim)        DELIM=${2?missing delimiter}; shift ;;
    -l|--lines)        DELIM=$'\n' ;;
    -q|--quiet)        QUIET=1 ;;
    -h|--help)         usage; exit 0 ;;
    -V|--version)      echo "$PROG $VERSION"; exit 0 ;;
    *)                 die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

command -v nmap >/dev/null || die "nmap not found; install it first"

# ---------- discover network ----------
GW=$(ip route | awk '/^default/ {print $3; exit}')
[[ -z $IFACE ]] && IFACE=$(ip route | awk '/^default/ {print $5; exit}')
[[ -z $IFACE ]] && die "no default route; pass --iface"
CIDR=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}')
[[ -z $CIDR ]] && die "no IPv4 address on $IFACE"
ME=${CIDR%/*}
[[ -z $SUBNET ]] && SUBNET=$CIDR

(( KEEP_GW )) || [[ -z $GW ]] || EXCLUDES+=("$GW")
(( KEEP_ME )) || EXCLUDES+=("$ME")

if (( ! QUIET )); then
  printf '\n  %s%s%s %sv%s%s\n' "$B" "$PROG" "$R" "$D" "$VERSION" "$R" >&2
  printf '  %s%s%s\n' "$D" "----------------------------------" "$R" >&2
  printf '  %-10s %s\n' "interface" "$IFACE" "subnet" "$SUBNET" \
         "gateway" "${GW:-none}" "this host" "$ME" >&2
  printf '  %-10s %s\n\n' "excluding" "${EXCLUDES[*]:-nothing}" >&2
fi
(( EUID == 0 )) || warn "not root: ARP discovery disabled, some hosts may be missed"

# ---------- scan with spinner ----------
TMP=$(mktemp) || die "mktemp failed"
trap 'rm -f "$TMP"; [[ -n ${PID:-} ]] && kill "$PID" 2>/dev/null; (( ${SPIN:-0} )) && printf "\e[?25h" >&2' EXIT
trap 'exit 130' INT TERM

START=$SECONDS
nmap -sn -n "$SUBNET" -oG "$TMP" >/dev/null 2>&1 & PID=$!

if (( ! QUIET )) && [[ -t 2 ]]; then
  frames='|/-\'; i=0; SPIN=1
  printf '\e[?25l' >&2
  while kill -0 "$PID" 2>/dev/null; do
    printf '\r  %s%s%s scanning %s ... %ds ' "$CYN" "${frames:i++%4:1}" "$R" \
           "$SUBNET" $((SECONDS - START)) >&2
    sleep 0.1
  done
  printf '\r\e[K\e[?25h' >&2
fi
wait "$PID"; RC=$?; PID=
(( RC == 0 )) || die "nmap exited with status $RC"

# ---------- results ----------
mapfile -t HOSTS < <(
  awk '/Status: Up/ {print $2}' "$TMP" \
  | grep -vxF -f <(printf '%s\n' "${EXCLUDES[@]}" ) \
  | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
)
TOTAL=$(grep -c 'Status: Up' "$TMP")

if (( ${#HOSTS[@]} )); then
  out=${HOSTS[0]}
  for h in "${HOSTS[@]:1}"; do out+=$DELIM$h; done
  printf '%s\n' "$out"
fi

if (( ! QUIET )); then
  printf '\n  %s%d%s host(s) listed %s(%d up, %d excluded) in %ds%s\n\n' \
    "$GRN$B" "${#HOSTS[@]}" "$R" "$D" "$TOTAL" $((TOTAL - ${#HOSTS[@]})) \
    $((SECONDS - START)) "$R" >&2
fi
