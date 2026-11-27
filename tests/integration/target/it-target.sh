#!/usr/bin/env bash
# Disposable integration target: Debian 12, systemd as PID 1, sshd, sudo, NET_ADMIN.
# Mock environment only, never production evidence.
#
#   eval "$(tests/integration/target/it-target.sh start)"   build image, recreate target, print ASTRARIUM_IT_* exports
#   tests/integration/target/it-target.sh env                 exports for running target
#   tests/integration/target/it-target.sh stop                remove target
#
# bbr: kernel of container host must offer tcp_bbr (modprobe, not persistent across podman machine restarts).
#
# Knobs: IT_TARGET_ENGINE (podman or docker, default podman when installed), IT_TARGET_NAME,
# IT_TARGET_IMAGE, IT_TARGET_PORT (default 2222), IT_TARGET_STATE (harness key dir, default ~/.cache/astrarium-it).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
name=${IT_TARGET_NAME:-astrarium-it}
image=${IT_TARGET_IMAGE:-localhost/astrarium-it-target:latest}
port=${IT_TARGET_PORT:-2222}
state=${IT_TARGET_STATE:-${XDG_CACHE_HOME:-$HOME/.cache}/astrarium-it}
login=astrarium

log() {
  printf 'it-target: %s\n' "$*" >&2
}

pick_engine() {
  if [ -n "${IT_TARGET_ENGINE:-}" ]; then
    printf '%s\n' "$IT_TARGET_ENGINE"
  elif command -v podman >/dev/null 2>&1; then
    printf 'podman\n'
  elif command -v docker >/dev/null 2>&1; then
    printf 'docker\n'
  else
    log "neither podman nor docker found"
    exit 1
  fi
}

run_target() {
  local engine=$1
  # docker may be podman under another name: flags follow real engine
  if "$engine" --version 2>/dev/null | grep -qi podman; then
    "$engine" run -d --name "$name" --hostname it-target --systemd=always --cap-add NET_ADMIN \
      -p "127.0.0.1:$port:22" "$image" >/dev/null
  else
    # unverified: no native docker run yet; privileged + host cgroupns gives container host-kernel access
    # systemd under docker on cgroup v2 needs writable cgroup tree, privileged also grants NET_ADMIN
    "$engine" run -d --name "$name" --hostname it-target --privileged --cgroupns=host \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
      -p "127.0.0.1:$port:22" "$image" >/dev/null
  fi
}

wait_ready() {
  local engine=$1 status=""
  for _ in $(seq 1 90); do
    status=$("$engine" exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$status" in
      running | degraded)
        if "$engine" exec "$name" systemctl is-active --quiet ssh; then
          return 0
        fi
        ;;
    esac
    sleep 1
  done
  log "target did not boot (systemctl is-system-running: ${status:-no answer})"
  exit 1
}

authorize_key() {
  "$1" exec -i "$name" sh -c "install -d -m 700 -o $login -g $login /home/$login/.ssh \
    && cat > /home/$login/.ssh/authorized_keys \
    && chown $login:$login /home/$login/.ssh/authorized_keys \
    && chmod 600 /home/$login/.ssh/authorized_keys" <"$state/id_ed25519.pub"
}

check_bbr() {
  if ! "$1" exec "$name" cat /proc/sys/net/ipv4/tcp_available_congestion_control | grep -qw bbr; then
    log "warning: kernel offers no bbr congestion control, test_kernel_offers_bbr and e2e deploy will fail"
    log "load it on container host, e.g. podman machine ssh sudo modprobe tcp_bbr"
  fi
}

print_env() {
  local engine=$1 mapped host_key target_id
  mapped=$("$engine" port "$name" 22/tcp | head -n 1)
  host_key=$("$engine" exec "$name" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1 " " $2}')
  target_id=$("$engine" exec "$name" cat /etc/astrarium-it-target)
  printf 'export ASTRARIUM_IT_HOST=%s\n' "${mapped%:*}"
  printf 'export ASTRARIUM_IT_PORT=%s\n' "${mapped##*:}"
  printf 'export ASTRARIUM_IT_USER=%s\n' "$login"
  printf 'export ASTRARIUM_IT_KEY=%q\n' "$state/id_ed25519"
  printf "export ASTRARIUM_IT_HOST_KEY='%s'\n" "$host_key"
  printf 'export ASTRARIUM_IT_TARGET_ID=%s\n' "$target_id"
}

start() {
  local engine
  engine=$(pick_engine)
  mkdir -p "$state"
  chmod 700 "$state"
  if [ ! -f "$state/id_ed25519" ]; then
    ssh-keygen -q -t ed25519 -N '' -C astrarium-it -f "$state/id_ed25519"
  fi
  log "building $image with $engine"
  "$engine" build -t "$image" -f "$here/Containerfile" "$here" >&2
  "$engine" rm -f "$name" >/dev/null 2>&1 || true
  log "starting $name on 127.0.0.1:$port"
  run_target "$engine"
  wait_ready "$engine"
  authorize_key "$engine"
  check_bbr "$engine"
  print_env "$engine"
}

case "${1:-}" in
  start) start ;;
  env) print_env "$(pick_engine)" ;;
  stop)
    "$(pick_engine)" rm -f "$name" >/dev/null
    log "removed $name"
    ;;
  *)
    printf 'usage: %s start|env|stop\n' "$0" >&2
    exit 2
    ;;
esac
