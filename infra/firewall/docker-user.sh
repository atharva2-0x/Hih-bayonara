#!/usr/bin/env bash
# Host firewall: defense in depth for DOUBLE-BLIND.
#
# Zone networks are already `internal` (no route out). This covers the one
# network that is not (net-ui, which carries only the operator listener) and
# protects against a future compose edit that accidentally drops `internal`:
#
#   * no container on 10.77.0.0/16 may open a NEW connection leaving 10.77.0.0/16
#   * nothing on 10.77.0.0/16 may reach the cloud metadata service
#   * replies to the operator's loopback-published port still work (ESTABLISHED)
#
# Usage: sudo infra/firewall/docker-user.sh [apply|remove|show]
set -euo pipefail
ZONES=10.77.0.0/16
TAG="doubleblind"

rules() {
  local op=$1
  iptables "$op" DOCKER-USER -s "$ZONES" -d 169.254.169.254/32 -m comment --comment "$TAG: no metadata" -j DROP
  iptables "$op" DOCKER-USER -s "$ZONES" ! -d "$ZONES" -m conntrack --ctstate NEW \
    -m comment --comment "$TAG: no egress" -j DROP
}

case "${1:-apply}" in
  apply)
    rules -C 2>/dev/null && { echo "already applied"; exit 0; }
    rules -I
    echo "applied DOCKER-USER rules for $ZONES" ;;
  remove)
    while rules -D 2>/dev/null; do :; done
    echo "removed" ;;
  show)
    iptables -L DOCKER-USER -n -v --line-numbers ;;
  *) echo "usage: $0 [apply|remove|show]"; exit 2 ;;
esac
