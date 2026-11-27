#!/usr/bin/env bash
# Node apply payload: swap xray config, HAProxy config and xray binary on one node with validation,
# health check and rollback. Runs as deploy user.
#
# Usage: bash apply.sh launch|apply|reconcile KEY=VALUE...
#   launch     copy itself to run dir (fresh inode), take exclusive flock on ~/.astrarium/lock,
#              start `apply` detached (setsid, nohup) holding inherited lock, return once it runs
#   apply      under lock: recheck plan, validate, back up, swap, restart, health check, roll back,
#              append steps and `result=` to ~/.astrarium/runs/<RUN>/state
#   reconcile  wait for lock (so apply has exited), print `result=` of last attempt,
#              finish interrupted swap, print `result=pending` when no swap happened
#
# Results: applied rejected rolled_back rollback_failed unhealthy_no_previous plan_changed
#          prerequisite locked unknown (reconcile only: pending)
#
# sudo argv matches deploy_access sudoers: mv, /usr/sbin/haproxy -c -f,
# systemctl restart xray, systemctl enable --now | disable --now | reload haproxy.

set -uo pipefail
umask 077

MODE="${1:-}"
shift || true
ARGS=("$@")

ROOT="${ASTRARIUM_ROOT:-}"
XRAY_CONFIG="$ROOT/usr/local/etc/xray/config.json"
HAPROXY_CONFIG="$ROOT/etc/haproxy/haproxy.cfg"
XRAY_BIN="$ROOT/usr/local/bin/xray"
HAPROXY_BIN="$ROOT/usr/sbin/haproxy"
BASE="$HOME/.astrarium"
LOCK="$BASE/lock"
NODE_STATE="$BASE/state"
KEEP_BACKUPS=3
KEEP_RUNS=10

RUN="" STAGE="" COMMIT=- EXPECT_COMMIT=- FORCE=0 SETTLE=3 LOCK_WAIT=30 WAIT=600
CONFIG_BEFORE=- HAPROXY_BEFORE=- XRAY_BEFORE=-
CONFIG_NEW=- HAPROXY_NEW=- XRAY_NEW=-
HAPROXY_INSTALLED=0 XRAY_EXPECT=-

for arg in "$@"; do
    key="${arg%%=*}"
    value="${arg#*=}"
    if [[ $arg != *=* || ! $value =~ ^[A-Za-z0-9._:/+-]*$ ]]; then
        echo "invalid parameter: $key" >&2
        exit 2
    fi
    case "$key" in
        RUN | STAGE | COMMIT | EXPECT_COMMIT | FORCE | SETTLE | LOCK_WAIT | WAIT | \
            CONFIG_BEFORE | HAPROXY_BEFORE | XRAY_BEFORE | CONFIG_NEW | HAPROXY_NEW | XRAY_NEW | \
            HAPROXY_INSTALLED | XRAY_EXPECT)
            printf -v "$key" '%s' "$value"
            ;;
        *)
            echo "unknown parameter: $key" >&2
            exit 2
            ;;
    esac
done
for key in SETTLE LOCK_WAIT WAIT; do
    if [[ ! ${!key} =~ ^[0-9]+$ ]]; then
        echo "$key must be whole seconds" >&2
        exit 2
    fi
done
if [[ ! $RUN =~ ^[A-Za-z0-9._-]+$ || $RUN == *..* ]]; then
    echo "RUN is required (no '..')" >&2
    exit 2
fi
if [[ $STAGE == *..* ]]; then
    echo "invalid STAGE" >&2
    exit 2
fi

RUN_DIR="$BASE/runs/$RUN"
STATE="$RUN_DIR/state"
BACKUP="$BASE/backup/$RUN"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
note() { printf '%s\n' "$1" >> "$STATE"; }

hash_of() {
    local sum
    if sum=$(sha256sum "$1" 2> /dev/null); then printf '%s\n' "${sum%% *}"; else printf -- '-\n'; fi
}

recorded_commit() {
    local commit
    commit=$(sed -n 's/^commit=//p' "$NODE_STATE" 2> /dev/null | tail -n 1)
    printf '%s\n' "${commit:--}"
}

haproxy_wanted() { grep -qiE '^[[:space:]]*(frontend|listen)[[:space:]]+[^[:space:]]' "$1" 2> /dev/null; }

start_haproxy() { sudo systemctl enable --now haproxy && sudo systemctl reload haproxy; }

# :443-safe order: HAProxy fronting -> restart xray first, xray on :443 -> stop HAProxy first.
restart_services() {
    if [ "$HAPROXY_INSTALLED" != 1 ]; then
        sudo systemctl restart xray
    elif haproxy_wanted "$HAPROXY_CONFIG"; then
        sudo systemctl restart xray && start_haproxy
    else
        sudo systemctl disable --now haproxy && sudo systemctl restart xray
    fi
}

healthy() {
    systemctl is-active --quiet xray || return 1
    if [ "$HAPROXY_INSTALLED" = 1 ] && haproxy_wanted "$HAPROXY_CONFIG"; then
        systemctl is-active --quiet haproxy || return 1
    fi
    return 0
}

settled_and_healthy() { sleep "$SETTLE" && healthy; }

plan_matches() {
    [ "$(hash_of "$XRAY_CONFIG")" = "$CONFIG_BEFORE" ] || return 1
    [ "$(hash_of "$XRAY_BIN")" = "$XRAY_BEFORE" ] || return 1
    if [ "$HAPROXY_INSTALLED" = 1 ] && [ "$(hash_of "$HAPROXY_CONFIG")" != "$HAPROXY_BEFORE" ]; then return 1; fi
    [ "$(recorded_commit)" = "$EXPECT_COMMIT" ]
}

staged_intact() {
    if [ "$CONFIG_NEW" != - ] && [ "$(hash_of "$STAGE/config.json")" != "$CONFIG_NEW" ]; then return 1; fi
    if [ "$HAPROXY_NEW" != - ] && [ "$(hash_of "$STAGE/haproxy.cfg")" != "$HAPROXY_NEW" ]; then return 1; fi
    if [ "$XRAY_NEW" != - ] && [ "$(hash_of "$STAGE/xray")" != "$XRAY_NEW" ]; then return 1; fi
    return 0
}

normalise_modes() {
    if [ "$CONFIG_NEW" != - ]; then chmod 0644 "$STAGE/config.json" || return 1; fi
    if [ "$HAPROXY_NEW" != - ]; then chmod 0644 "$STAGE/haproxy.cfg" || return 1; fi
    if [ "$XRAY_NEW" != - ]; then chmod 0755 "$STAGE/xray" || return 1; fi
    return 0
}

xray_reports_expected() {
    local line
    line=$("$1" version 2> /dev/null | head -n 1)
    case "$XRAY_EXPECT" in
        -) [ -n "$line" ] ;;
        version:*) [ "$(printf '%s\n' "$line" | awk '{ print $2 }')" = "${XRAY_EXPECT#version:}" ] ;;
        build:*) [[ $line == *") ${XRAY_EXPECT#build:} ("* ]] ;;
        *) return 1 ;;
    esac
}

validate() {
    local bin="$XRAY_BIN" config="$XRAY_CONFIG"
    if [ "$XRAY_NEW" != - ]; then
        bin="$STAGE/xray"
        if ! xray_reports_expected "$bin"; then
            log "staged xray does not report $XRAY_EXPECT"
            return 1
        fi
    fi
    if [ "$CONFIG_NEW" != - ]; then config="$STAGE/config.json"; fi
    if ! "$bin" run -test -config "$config"; then
        log "config.json rejected by 'xray run -test'"
        return 1
    fi
    if [ "$HAPROXY_NEW" != - ] && haproxy_wanted "$STAGE/haproxy.cfg"; then
        if ! sudo "$HAPROXY_BIN" -c -f "$STAGE/haproxy.cfg"; then
            log "haproxy.cfg rejected by 'haproxy -c'"
            return 1
        fi
    fi
    return 0
}

backup_live() {
    mkdir -p "$BACKUP" && chmod 0700 "$BACKUP" || return 1
    if [ "$CONFIG_NEW" != - ] && [ -f "$XRAY_CONFIG" ]; then cp -p "$XRAY_CONFIG" "$BACKUP/config.json" || return 1; fi
    if [ "$HAPROXY_NEW" != - ] && [ -f "$HAPROXY_CONFIG" ]; then cp -p "$HAPROXY_CONFIG" "$BACKUP/haproxy.cfg" || return 1; fi
    if [ "$XRAY_NEW" != - ]; then cp -p "$XRAY_BIN" "$BACKUP/xray" || return 1; fi
    return 0
}

has_previous() { [ -f "$BACKUP/config.json" ] || [ -f "$BACKUP/haproxy.cfg" ] || [ -f "$BACKUP/xray" ]; }

swap_one() { touch "$1" && sudo mv "$1" "$2"; }

swap() {
    note step=swapping
    if [ "$CONFIG_NEW" != - ]; then swap_one "$STAGE/config.json" "$XRAY_CONFIG" || return 1; fi
    if [ "$HAPROXY_NEW" != - ]; then swap_one "$STAGE/haproxy.cfg" "$HAPROXY_CONFIG" || return 1; fi
    if [ "$XRAY_NEW" != - ]; then swap_one "$STAGE/xray" "$XRAY_BIN" || return 1; fi
    note step=swapped
}

# No backup means file was absent before run: move new file out of live path into run dir.
restore() {
    if [ -f "$BACKUP/$1" ]; then
        cp -p "$BACKUP/$1" "$STAGE/$1.restore" && sudo mv "$STAGE/$1.restore" "$2"
    elif [ -e "$2" ]; then
        sudo mv "$2" "$RUN_DIR/$1.removed"
    fi
}

rollback() {
    local failed=0
    if [ "$CONFIG_NEW" != - ]; then restore config.json "$XRAY_CONFIG" || failed=1; fi
    if [ "$HAPROXY_NEW" != - ]; then restore haproxy.cfg "$HAPROXY_CONFIG" || failed=1; fi
    if [ "$XRAY_NEW" != - ]; then restore xray "$XRAY_BIN" || failed=1; fi
    return "$failed"
}

write_node_state() {
    local tmp="$NODE_STATE.$$"
    {
        printf 'commit=%s\nrun=%s\n' "$COMMIT" "$RUN"
        printf 'config=%s\nhaproxy=%s\nxray=%s\n' "$(hash_of "$XRAY_CONFIG")" "$(hash_of "$HAPROXY_CONFIG")" "$(hash_of "$XRAY_BIN")"
        printf 'time=%s\n' "$(date +%s)"
    } > "$tmp" && mv -f "$tmp" "$NODE_STATE" && return 0
    rm -f "$tmp"
    return 1
}

prune() {
    local dir
    ls -1dt -- "$BASE"/backup/*/ 2> /dev/null | tail -n +$((KEEP_BACKUPS + 1)) | while IFS= read -r dir; do rm -rf -- "$dir"; done
    ls -1dt -- "$BASE"/runs/*/ 2> /dev/null | tail -n +$((KEEP_RUNS + 1)) | while IFS= read -r dir; do rm -rf -- "$dir"; done
}

# Node state lands before `result=applied`, failed write -> `unknown` (swapped but commit not recorded).
finish() {
    local result=$1
    if [ "$result" = applied ] && ! write_node_state; then
        log "node state write failed"
        result=unknown
    fi
    note "result=$result"
    log "result: $result"
    if [ "$result" != locked ]; then prune; fi
    exit 0
}

cleanup() {
    if [[ -n $STAGE && $STAGE == "$RUN_DIR"/stage.* ]]; then rm -rf -- "$STAGE"; fi
}

do_apply() {
    trap cleanup EXIT
    mkdir -p "$RUN_DIR" || exit 1
    note "pid=$$"
    if [ "${ASTRARIUM_LOCKED:-0}" != 1 ]; then
        exec 9>> "$LOCK"
        flock -w "$LOCK_WAIT" 9 || finish locked
    fi
    note step=locked
    log "run $RUN commit $COMMIT"
    if [[ $STAGE != "$RUN_DIR"/stage.* || ! -d $STAGE ]]; then
        log "invalid STAGE"
        finish rejected
    fi
    [ -x "$XRAY_BIN" ] || finish prerequisite
    if [ "$FORCE" != 1 ] && ! plan_matches; then finish plan_changed; fi
    note step=checked
    if ! staged_intact || ! normalise_modes || ! validate; then finish rejected; fi
    note step=validated
    if ! backup_live; then
        log "backup failed"
        finish rejected
    fi
    note step=backup
    if swap && restart_services && settled_and_healthy; then finish applied; fi
    note step=unhealthy
    log "services unhealthy after swap, rolling back"
    systemctl --no-pager --lines=10 status xray 2>&1 || true
    has_previous || finish unhealthy_no_previous
    if rollback && restart_services && settled_and_healthy; then finish rolled_back; fi
    finish rollback_failed
}

need_tools() {
    local tool
    for tool in flock setsid sha256sum; do
        if ! command -v "$tool" > /dev/null; then
            echo "missing $tool" >&2
            exit 3
        fi
    done
}

do_launch() {
    need_tools
    mkdir -p "$RUN_DIR" && chmod 0700 "$BASE" "$RUN_DIR" || exit 1
    if [ "$(readlink -f "$0")" != "$(readlink -f "$RUN_DIR/apply.sh")" ]; then
        # Temp file + rename: running apply keeps reading its own inode.
        local tmp="$RUN_DIR/apply.sh.$$"
        if ! { cp -f "$0" "$tmp" && mv -f "$tmp" "$RUN_DIR/apply.sh"; }; then
            rm -f "$tmp"
            exit 1
        fi
    fi
    exec 9>> "$LOCK"
    if ! flock -w "$LOCK_WAIT" 9; then
        printf 'launched=%s\nresult=locked\n' "$(date +%s)" >> "$STATE"
        echo result=locked
        return
    fi
    printf 'launched=%s\n' "$(date +%s)" >> "$STATE" || exit 1
    ASTRARIUM_LOCKED=1 setsid nohup bash "$RUN_DIR/apply.sh" apply "${ARGS[@]}" >> "$RUN_DIR/apply.log" 2>&1 < /dev/null &
    local _
    for _ in $(seq 50); do
        if last_attempt | grep -q '^pid='; then break; fi
        sleep 0.1
    done
    echo launched
}

last_attempt() {
    [ -f "$STATE" ] || return 0
    awk '/^launched=/ { block = "" } { block = block $0 "\n" } END { printf "%s", block }' "$STATE"
}

new_files_live() {
    if [ "$CONFIG_NEW" != - ] && [ "$(hash_of "$XRAY_CONFIG")" != "$CONFIG_NEW" ]; then return 1; fi
    if [ "$HAPROXY_NEW" != - ] && [ "$(hash_of "$HAPROXY_CONFIG")" != "$HAPROXY_NEW" ]; then return 1; fi
    if [ "$XRAY_NEW" != - ] && [ "$(hash_of "$XRAY_BIN")" != "$XRAY_NEW" ]; then return 1; fi
    return 0
}

started_after_swap() {
    local since started newest=0 path mtime
    local -a paths=()
    if [ "$CONFIG_NEW" != - ]; then paths+=("$XRAY_CONFIG"); fi
    if [ "$HAPROXY_NEW" != - ]; then paths+=("$HAPROXY_CONFIG"); fi
    if [ "$XRAY_NEW" != - ]; then paths+=("$XRAY_BIN"); fi
    since=$(TZ=UTC systemctl show -p ActiveEnterTimestamp --value xray 2> /dev/null)
    [ -n "$since" ] || return 1
    started=$(date -d "$since" +%s 2> /dev/null) || return 1
    for path in "${paths[@]}"; do
        mtime=$(stat -c %Y "$path" 2> /dev/null) || continue
        if [ "$mtime" -gt "$newest" ]; then newest=$mtime; fi
    done
    [ "$started" -gt "$newest" ]
}

reconciled() {
    note "result=$1"
    echo "result=$1"
}

repair() {
    if ! new_files_live; then
        reconciled unknown
        return
    fi
    if ! started_after_swap; then
        log "reconcile: xray started before the swap, restarting"
        if ! restart_services; then
            log "reconcile: restart failed"
            reconciled unknown
            return
        fi
        sleep "$SETTLE"
    elif [ "$HAPROXY_NEW" != - ] && [ "$HAPROXY_INSTALLED" = 1 ] && haproxy_wanted "$HAPROXY_CONFIG"; then
        # xray restart may have happened without haproxy reload (apply killed in between).
        log "reconcile: xray started after the swap, reloading haproxy"
        if ! start_haproxy; then
            log "reconcile: haproxy reload failed"
            reconciled unknown
            return
        fi
        sleep "$SETTLE"
    fi
    if ! healthy; then
        reconciled unknown
    elif ! write_node_state; then
        log "reconcile: node state write failed"
        reconciled unknown
    else
        reconciled applied
    fi
}

do_reconcile() {
    local block
    mkdir -p "$BASE" || exit 1
    exec 9>> "$LOCK"
    if ! flock -w "$WAIT" 9; then
        echo result=unknown
        return
    fi
    block=$(last_attempt)
    if grep -q '^result=' <<< "$block"; then
        grep '^result=' <<< "$block" | tail -n 1
    elif grep -qx 'step=swapping' <<< "$block"; then
        repair
    else
        echo result=pending
    fi
}

case "$MODE" in
    launch) do_launch ;;
    apply) do_apply ;;
    reconcile) do_reconcile ;;
    *)
        echo "usage: apply.sh launch|apply|reconcile KEY=VALUE..." >&2
        exit 2
        ;;
esac
