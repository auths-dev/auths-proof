#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'qualification row services: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" && ! -L "$1" ]] || die "required regular file is absent: $1"
}

row_ids() {
  jq -er '.runs | map(.id) | if length > 0 and length == (unique | length) then .[] else error("invalid row roster") end' "$MATRIX"
}

row_runtime() {
  printf '%s/%s\n' "$RUNTIME_ROOT" "$1"
}

policy_value() {
  local source="$1" field="$2" now matches
  now="$(date +%s)"
  matches="$(jq -cer \
    --arg source "$source" \
    --arg domain "$DOMAIN" \
    --argjson now "$now" \
    '[.keys[] | select(.source == $source and (.allowedDomains | index($domain)) != null and .notBeforeUnixSeconds <= $now and (.notAfterUnixSeconds == 0 or $now < .notAfterUnixSeconds))] | if length == 1 then .[0] else error("source policy is not unique and current") end' \
    "$SOURCE_TRUST")"
  jq -er --arg field "$field" '.[$field] // error("source policy field is absent")' <<<"$matches"
}

record_pid() {
  local runtime="$1" name="$2" pid="$3" starttime process_group session deadline
  install -d -m 0700 "$runtime/pids" "$runtime/logs"
  deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )); do
    if [[ -r "/proc/$pid/stat" ]]; then
      starttime="$(awk '{print $22}' "/proc/$pid/stat")"
      process_group="$(awk '{print $5}' "/proc/$pid/stat")"
      session="$(awk '{print $6}' "/proc/$pid/stat")"
      if [[ "$starttime" =~ ^[0-9]+$ && "$process_group" == "$pid" && "$session" == "$pid" ]]; then
        printf '%s\n' "$pid" >"$runtime/pids/$name.pid"
        printf '%s\n' "$starttime" >"$runtime/pids/$name.starttime"
        return 0
      fi
    fi
    sleep 0.01
  done
  die "service process did not establish its retained session identity: $name"
}

retained_process_is_live() {
  local file="$1" pid expected actual
  [[ ! -f "${file%.pid}.status" ]] || return 1
  pid="$(<"$file")"
  expected="$(<"${file%.pid}.starttime")"
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$expected" =~ ^[0-9]+$ && -r "/proc/$pid/stat" ]] || return 1
  actual="$(awk '{print $22}' "/proc/$pid/stat")"
  [[ "$actual" == "$expected" ]]
}

start_background() {
  local runtime="$1" name="$2" uid="$3" gid="$4" monitor deadline tracking tracking_set=0
  shift 4
  install -d -m 0700 "$runtime/pids" "$runtime/logs"
  if [[ ${RUNNER_TRACKING_ID+x} == x ]]; then
    tracking="$RUNNER_TRACKING_ID"
    tracking_set=1
    unset RUNNER_TRACKING_ID
  fi
  (
    local status=0 service_pid
    setsid --wait setpriv --reuid "$uid" --regid "$gid" --clear-groups env -i "$@" </dev/null &
    service_pid=$!
    trap 'kill -KILL -- "-$service_pid" 2>/dev/null || true' EXIT
    record_pid "$runtime" "$name" "$service_pid"
    wait "$service_pid" || status=$?
    trap - EXIT
    printf '%s\n' "$status" >"$runtime/pids/$name.status"
    exit "$status"
  ) >"$runtime/logs/$name.log" 2>&1 &
  monitor=$!
  if (( tracking_set == 1 )); then
    export RUNNER_TRACKING_ID="$tracking"
  fi
  deadline=$((SECONDS + 5))
  while [[ ! -f "$runtime/pids/$name.pid" && ! -f "$runtime/pids/$name.status" && $SECONDS -lt $deadline ]]; do
    kill -0 "$monitor" 2>/dev/null || break
    sleep 0.01
  done
  [[ -f "$runtime/pids/$name.pid" ]] || die "service failed before retaining its identity: $name"
}

start_seeded_background() {
  local runtime="$1" name="$2" uid="$3" gid="$4" monitor deadline tracking tracking_set=0
  shift 4
  install -d -m 0700 "$runtime/pids" "$runtime/logs"
  if [[ ${RUNNER_TRACKING_ID+x} == x ]]; then
    tracking="$RUNNER_TRACKING_ID"
    tracking_set=1
    unset RUNNER_TRACKING_ID
  fi
  (
    local status=0 service_pid
    setsid --wait setpriv --reuid "$uid" --regid "$gid" --clear-groups env -i "$@" \
      <<<"$QUALIFICATION_SOURCE_SEED" &
    service_pid=$!
    trap 'kill -KILL -- "-$service_pid" 2>/dev/null || true' EXIT
    record_pid "$runtime" "$name" "$service_pid"
    wait "$service_pid" || status=$?
    trap - EXIT
    printf '%s\n' "$status" >"$runtime/pids/$name.status"
    exit "$status"
  ) >"$runtime/logs/$name.log" 2>&1 &
  monitor=$!
  if (( tracking_set == 1 )); then
    export RUNNER_TRACKING_ID="$tracking"
  fi
  deadline=$((SECONDS + 5))
  while [[ ! -f "$runtime/pids/$name.pid" && ! -f "$runtime/pids/$name.status" && $SECONDS -lt $deadline ]]; do
    kill -0 "$monitor" 2>/dev/null || break
    sleep 0.01
  done
  [[ -f "$runtime/pids/$name.pid" ]] || die "seeded service failed before retaining its identity: $name"
}

start_runtime_read_background() {
  local runtime="$1" name="$2" uid="$3" gid="$4" monitor deadline tracking tracking_set=0
  shift 4
  install -d -m 0700 "$runtime/pids" "$runtime/logs"
  if [[ ${RUNNER_TRACKING_ID+x} == x ]]; then
    tracking="$RUNNER_TRACKING_ID"
    tracking_set=1
    unset RUNNER_TRACKING_ID
  fi
  (
    local status=0 service_pid
    printf '%s' "$QUALIFICATION_RUNTIME_READ_CREDENTIAL" \
      | setsid --wait setpriv --reuid "$uid" --regid "$gid" --clear-groups env -i "$@" &
    service_pid=$!
    trap 'kill -KILL -- "-$service_pid" 2>/dev/null || true' EXIT
    record_pid "$runtime" "$name" "$service_pid"
    wait "$service_pid" || status=$?
    trap - EXIT
    printf '%s\n' "$status" >"$runtime/pids/$name.status"
    exit "$status"
  ) >"$runtime/logs/$name.log" 2>&1 &
  monitor=$!
  if (( tracking_set == 1 )); then
    export RUNNER_TRACKING_ID="$tracking"
  fi
  deadline=$((SECONDS + 5))
  while [[ ! -f "$runtime/pids/$name.pid" && ! -f "$runtime/pids/$name.status" && $SECONDS -lt $deadline ]]; do
    kill -0 "$monitor" 2>/dev/null || break
    sleep 0.01
  done
  [[ -f "$runtime/pids/$name.pid" ]] || die "runtime-read service failed before retaining its identity: $name"
}

wait_for_socket() {
  local socket="$1" pid="$2" deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    [[ -S "$socket" ]] && return 0
    kill -0 "$pid" 2>/dev/null || die "service exited before socket readiness: $socket"
    sleep 0.05
  done
  die "service did not create its socket: $socket"
}

start_appender() {
  local uid gid row runtime
  while read -r row; do
    runtime="$(row_runtime "$row")"
    uid="$(jq -er '.supervisorControllerUid' "$runtime/ledger-plan.json")"
    gid="$(jq -er '.agentGid' "$runtime/ledger-plan.json")"
    start_background "$runtime" appender "$uid" "$gid" \
      "$TOOLS/auths-qualification-supervisor" serve-append-session \
      --plan "$runtime/ledger-plan.json" \
      --common-root "$COMMON_ROOT" \
      --source-trust "$runtime/source-trust.json" \
      --socket "$runtime/sequencer.sock"
    wait_for_socket "$runtime/sequencer.sock" "$(<"$runtime/pids/appender.pid")"
  done < <(row_ids)
}

source_binary() {
  case "$1" in
    supervisor) printf '%s/qualification-source-supervisor\n' "$TOOLS" ;;
    client-proxy) printf '%s/qualification-source-client-proxy\n' "$TOOLS" ;;
    journal-reader) printf '%s/qualification-source-journal-reader\n' "$TOOLS" ;;
    credential-broker) printf '%s/qualification-source-credential-broker\n' "$TOOLS" ;;
    profile-state-reader) printf '%s/qualification-source-profile-state-reader\n' "$TOOLS" ;;
    receipt-verifier) printf '%s/qualification-source-receipt-verifier\n' "$TOOLS" ;;
    provider-proxy) printf '%s/qualification-source-provider-proxy\n' "$TOOLS" ;;
    provider-observer) printf '%s/qualification-source-provider-observer\n' "$TOOLS" ;;
    *) die "unsupported source role: $1" ;;
  esac
}

start_source() {
  local source="$1" uid gid row runtime binary role_dir
  [[ -n "${QUALIFICATION_SOURCE_SEED:-}" ]] || die "source seed is absent"
  uid="$(policy_value "$source" sourceUid)"
  gid="$AGENT_GID"
  binary="$(source_binary "$source")"
  require_file "$binary"
  case "$source" in
    supervisor) role_dir=supervisor ;;
    client-proxy) role_dir=client-proxy-signer ;;
    journal-reader) role_dir=journal-reader ;;
    credential-broker) role_dir=credential-broker-signer ;;
    profile-state-reader) role_dir=profile-state-signer ;;
    receipt-verifier) role_dir=receipt-verifier-signer ;;
    provider-proxy) role_dir=provider-proxy-signer ;;
    provider-observer) role_dir=provider-observer-signer ;;
  esac
  while read -r row; do
    runtime="$(row_runtime "$row")"
    install -d -m 0700 "$runtime/pids" "$runtime/logs"
    if [[ "$source" == supervisor ]]; then
      start_seeded_background "$runtime" "$source" "$uid" "$gid" \
        "$binary" serve-ordinary-row-session \
        --socket "$runtime/supervisor/source.sock" \
        --ledger-plan "$runtime/$role_dir/ledger-plan.json" \
        --source-trust "$runtime/$role_dir/source-trust.json"
      wait_for_socket "$runtime/supervisor/source.sock" "$(<"$runtime/pids/$source.pid")"
    elif [[ "$source" == journal-reader ]]; then
      start_seeded_background "$runtime" "$source" "$uid" "$gid" \
        "$binary" serve-ordinary-row-session \
        --runtime-root "$runtime" \
        --sequencer-socket "$runtime/sequencer.sock" \
        --source-trust "$runtime/$role_dir/source-trust.json" \
        --ledger-plan "$runtime/$role_dir/ledger-plan.json" \
        --receipt-trust "$runtime/$role_dir/receipt-trust.json"
    else
      start_seeded_background "$runtime" "$source" "$uid" "$gid" \
        "$binary" serve-session \
        --socket "$runtime/$role_dir/source.sock" \
        --source-trust "$runtime/$role_dir/source-trust.json" \
        --ledger-plan "$runtime/$role_dir/ledger-plan.json"
      wait_for_socket "$runtime/$role_dir/source.sock" "$(<"$runtime/pids/$source.pid")"
    fi
  done < <(row_ids)
}

start_provider_observer_readers() {
  local row runtime uid gid binary first_scenario first_phase
  [[ -n "${QUALIFICATION_RUNTIME_READ_CREDENTIAL:-}" ]] \
    || die "ProviderObserver runtime-read credential is absent"
  uid="$(policy_value provider-observer readerUid)"
  binary="$(source_binary provider-observer)"
  require_file "$binary"
  while read -r row; do
    runtime="$(row_runtime "$row")"
    gid="$(jq -er '.agentGid' "$runtime/ledger-plan.json")"
    start_runtime_read_background "$runtime" provider-observer-reader "$uid" "$gid" \
      "$binary" serve-ordinary-row-session \
      --runtime-root "$runtime" \
      --signer-socket "$runtime/provider-observer-signer/source.sock" \
      --sequencer-socket "$runtime/sequencer.sock" \
      --ledger-plan "$runtime/provider-observer-reader/ledger-plan.json" \
      --source-trust "$runtime/provider-observer-reader/source-trust.json"
    first_scenario="$(jq -er '.phases[0].scenarioId' "$runtime/ledger-plan.json")"
    first_phase="$(jq -er '.phases[0].phaseIndex' "$runtime/ledger-plan.json")"
    wait_for_socket \
      "$runtime/$first_scenario/phase-$first_phase/provider-observer/controller.sock" \
      "$(<"$runtime/pids/provider-observer-reader.pid")"
  done < <(row_ids)
}

start_readers() {
  local row runtime uid gid binary first_scenario first_phase
  while read -r row; do
    runtime="$(row_runtime "$row")"
    gid="$(jq -er '.agentGid' "$runtime/ledger-plan.json")"

    uid="$(policy_value client-proxy readerUid)"
    binary="$(source_binary client-proxy)"
    start_background "$runtime" client-proxy-reader "$uid" "$gid" \
      "$binary" serve-ordinary-row-session \
      --runtime-root "$runtime" \
      --signer-socket "$runtime/client-proxy-signer/source.sock" \
      --sequencer-socket "$runtime/sequencer.sock" \
      --ledger-plan "$runtime/client-proxy-reader/ledger-plan.json" \
      --source-trust "$runtime/client-proxy-reader/source-trust.json"

    uid="$(policy_value credential-broker readerUid)"
    binary="$(source_binary credential-broker)"
    start_background "$runtime" credential-broker-reader "$uid" "$gid" \
      "$binary" serve-ordinary-row-session \
      --runtime-root "$runtime" \
      --signer-socket "$runtime/credential-broker-signer/source.sock" \
      --sequencer-socket "$runtime/sequencer.sock" \
      --ledger-plan "$runtime/credential-broker-reader/ledger-plan.json" \
      --source-trust "$runtime/credential-broker-reader/source-trust.json" \
      --connection-store "$runtime/credential-broker-store/connections.cbor" \
      --credential-store "$runtime/credential-broker-store/credentials.cbor"

    uid="$(policy_value profile-state-reader readerUid)"
    binary="$(source_binary profile-state-reader)"
    start_background "$runtime" profile-state-reader "$uid" "$gid" \
      "$binary" serve-ordinary-row-session \
      --runtime-root "$runtime" \
      --signer-socket "$runtime/profile-state-signer/source.sock" \
      --sequencer-socket "$runtime/sequencer.sock" \
      --ledger-plan "$runtime/profile-state-reader/ledger-plan.json" \
      --source-trust "$runtime/profile-state-reader/source-trust.json"

    uid="$(policy_value receipt-verifier readerUid)"
    binary="$(source_binary receipt-verifier)"
    start_background "$runtime" receipt-verifier "$uid" "$gid" \
      "$binary" serve-ordinary-row-session \
      --runtime-root "$runtime" \
      --signer-socket "$runtime/receipt-verifier-signer/source.sock" \
      --sequencer-socket "$runtime/sequencer.sock" \
      --ledger-plan "$runtime/receipt-verifier-reader/ledger-plan.json" \
      --source-trust "$runtime/receipt-verifier-reader/source-trust.json" \
      --receipt-trust "$runtime/receipt-verifier-reader/receipt-trust.json"

    uid="$(policy_value provider-proxy readerUid)"
    binary="$(source_binary provider-proxy)"
    start_background "$runtime" provider-proxy "$uid" "$gid" \
      "$binary" serve-ordinary-row-session \
      --runtime-root "$runtime" \
      --signer-socket "$runtime/provider-proxy-signer/source.sock" \
      --sequencer-socket "$runtime/sequencer.sock" \
      --ledger-plan "$runtime/provider-proxy-reader/ledger-plan.json" \
      --source-trust "$runtime/provider-proxy-reader/source-trust.json"

    first_scenario="$(jq -er '.phases[0].scenarioId' "$runtime/ledger-plan.json")"
    first_phase="$(jq -er '.phases[0].phaseIndex' "$runtime/ledger-plan.json")"
    wait_for_socket "$runtime/$first_scenario/phase-$first_phase/client-proxy/client.sock" "$(<"$runtime/pids/client-proxy-reader.pid")"
    wait_for_socket "$runtime/$first_scenario/phase-$first_phase/credential-broker/agent.sock" "$(<"$runtime/pids/credential-broker-reader.pid")"
    wait_for_socket "$runtime/$first_scenario/phase-$first_phase/profile-state-reader/controller.sock" "$(<"$runtime/pids/profile-state-reader.pid")"
    wait_for_socket "$runtime/$first_scenario/phase-$first_phase/receipt-verifier/controller.sock" "$(<"$runtime/pids/receipt-verifier.pid")"
    wait_for_socket "$runtime/$first_scenario/phase-$first_phase/provider-proxy/agent.sock" "$(<"$runtime/pids/provider-proxy.pid")"
    wait_for_socket "$runtime/$first_scenario/phase-$first_phase/journal-reader/boundary.sock" "$(<"$runtime/pids/journal-reader.pid")"
  done < <(row_ids)
}

wait_all() {
  local row runtime file status=0 deadline service_status
  while read -r row; do
    runtime="$(row_runtime "$row")"
    deadline="$(jq -er '.deadlineAtUnixSeconds' "$runtime/ledger-plan.json")"
    for file in "$runtime"/pids/*.pid; do
      [[ -e "$file" ]] || continue
      while [[ ! -f "${file%.pid}.status" && "$(date +%s)" -lt "$deadline" ]]; do
        sleep 0.1
      done
      if [[ ! -f "${file%.pid}.status" ]]; then
        printf 'service exceeded row deadline: %s\n' "${file##*/}" >&2
        status=1
        continue
      fi
      service_status="$(<"${file%.pid}.status")"
      if [[ "$service_status" != 0 ]]; then
        printf 'service failed (%s): %s\n' "$service_status" "${file##*/}" >&2
        status=1
      fi
    done
  done < <(row_ids)
  return "$status"
}

stop_all() {
  local row runtime file pid deadline live plan policy cgroup status=0
  local agent_sha256='' current_agent_sha256 launcher_sha256 config_sha256
  launcher_sha256="$(sha256sum "$TOOLS/qualification-agent-launcher" | awk '{print $1}')"
  config_sha256="$(sha256sum "$AGENT_CONFIG" | awk '{print $1}')"
  [[ "$launcher_sha256" =~ ^[0-9a-f]{64}$ && "$config_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || die "protected install source digests are invalid"
  while read -r row; do
    current_agent_sha256="$(jq -er '.agentExecutableSha256' "$POLICY_ROOT/$row/ledger-plan.json")"
    [[ "$current_agent_sha256" =~ ^[0-9a-f]{64}$ ]] || die "row agent digest is invalid"
    if [[ -z "$agent_sha256" ]]; then
      agent_sha256="$current_agent_sha256"
    elif [[ "$agent_sha256" != "$current_agent_sha256" ]]; then
      die "row plans disagree on the installed qualification agent"
    fi
  done < <(row_ids)
  while read -r row; do
    runtime="$(row_runtime "$row")"
    for file in "$runtime"/pids/*.pid; do
      [[ -e "$file" ]] || continue
      retained_process_is_live "$file" || continue
      pid="$(<"$file")"
      kill -TERM -- "-$pid" 2>/dev/null || true
    done
  done < <(row_ids)
  deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )); do
    local live=0
    while read -r row; do
      runtime="$(row_runtime "$row")"
      for file in "$runtime"/pids/*.pid; do
        [[ -e "$file" ]] || continue
        retained_process_is_live "$file" && live=1
      done
    done < <(row_ids)
    (( live == 0 )) && break
    sleep 0.1
  done
  while read -r row; do
    runtime="$(row_runtime "$row")"
    for file in "$runtime"/pids/*.pid; do
      [[ -e "$file" ]] || continue
      retained_process_is_live "$file" || continue
      pid="$(<"$file")"
      kill -KILL -- "-$pid" 2>/dev/null || true
    done
  done < <(row_ids)
  deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )); do
    live=0
    while read -r row; do
      runtime="$(row_runtime "$row")"
      for file in "$runtime"/pids/*.pid; do
        [[ -e "$file" ]] || continue
        retained_process_is_live "$file" && live=1
      done
    done < <(row_ids)
    (( live == 0 )) && break
    sleep 0.1
  done
  while read -r row; do
    runtime="$(row_runtime "$row")"
    for file in "$runtime"/pids/*.pid; do
      [[ -e "$file" ]] || continue
      if retained_process_is_live "$file"; then
        printf 'retained service survived exact process-group cleanup: %s\n' "${file##*/}" >&2
        status=1
      fi
    done
  done < <(row_ids)
  (( status == 0 )) || return "$status"

  while read -r row; do
    runtime="$(row_runtime "$row")"
    policy="$POLICY_ROOT/$row"
    plan="$policy/ledger-plan.json"
    cgroup="$CGROUP_ROOT_PREFIX-$row"
    "$TOOLS/auths-qualification-supervisor" cleanup-row-runtime \
      --plan "$plan" \
      --runtime-root "$runtime" \
      --policy-root "$policy" \
      --cgroup-root "$cgroup" || status=1
  done < <(row_ids)
  (( status == 0 )) || return "$status"
  [[ -d "$RUNTIME_ROOT" && ! -L "$RUNTIME_ROOT" ]] || die "runtime parent changed before cleanup"
  [[ -d "$POLICY_ROOT" && ! -L "$POLICY_ROOT" ]] || die "policy parent changed before cleanup"
  rmdir -- "$RUNTIME_ROOT" "$POLICY_ROOT"
  "$TOOLS/auths-qualification-supervisor" cleanup-protected-install \
    --root "$PROTECTED_BIN_ROOT" \
    --agent-sha256 "$agent_sha256" \
    --launcher-sha256 "$launcher_sha256" \
    --config-sha256 "$config_sha256"
}

materialize_agent_key() {
  local role="$1" row runtime plan
  case "$role" in
    decision|execution|recovery) ;;
    *) die "invalid agent signing role: $role" ;;
  esac
  [[ -n "${QUALIFICATION_AGENT_SIGNING_SEED:-}" ]] || die "agent signing seed is absent"
  while read -r row; do
    runtime="$(row_runtime "$row")"
    plan="$POLICY_ROOT/$row/ledger-plan.json"
    require_file "$plan"
    printf '%s\n' "$QUALIFICATION_AGENT_SIGNING_SEED" | sudo env -i \
      "$TOOLS/auths-qualification-supervisor" materialize-agent-signing-key \
      --role "$role" \
      --plan "$plan" \
      --config "$AGENT_CONFIG" \
      --runtime-root "$runtime"
  done < <(row_ids)
}

[[ $# -ge 1 ]] || die "missing command"
COMMAND="$1"
shift

if [[ "$COMMAND" == materialize-agent-key ]]; then
  [[ $# == 1 ]] || die "materialize-agent-key requires one role"
  : "${TOOLS:?TOOLS is required}"
  : "${MATRIX:?MATRIX is required}"
  : "${RUNTIME_ROOT:?RUNTIME_ROOT is required}"
  : "${POLICY_ROOT:?POLICY_ROOT is required}"
  : "${AGENT_CONFIG:?AGENT_CONFIG is required}"
  require_file "$MATRIX"
  require_file "$AGENT_CONFIG"
  materialize_agent_key "$1"
  exit 0
fi

: "${TOOLS:?TOOLS is required}"
: "${MATRIX:?MATRIX is required}"
: "${RUNTIME_ROOT:?RUNTIME_ROOT is required}"
: "${SOURCE_TRUST:?SOURCE_TRUST is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${AGENT_GID:?AGENT_GID is required}"
require_file "$MATRIX"
require_file "$SOURCE_TRUST"

case "$COMMAND" in
  start-appender)
    : "${COMMON_ROOT:?COMMON_ROOT is required}"
    start_appender
    ;;
  start-source)
    [[ $# == 1 ]] || die "start-source requires one role"
    start_source "$1"
    ;;
  start-readers) start_readers ;;
  start-provider-observer-readers)
    : "${QUALIFICATION_RUNTIME_READ_CREDENTIAL:?QUALIFICATION_RUNTIME_READ_CREDENTIAL is required}"
    start_provider_observer_readers
    ;;
  wait) wait_all ;;
  stop)
    : "${POLICY_ROOT:?POLICY_ROOT is required}"
    : "${CGROUP_ROOT_PREFIX:?CGROUP_ROOT_PREFIX is required}"
    : "${PROTECTED_BIN_ROOT:?PROTECTED_BIN_ROOT is required}"
    : "${AGENT_CONFIG:?AGENT_CONFIG is required}"
    require_file "$AGENT_CONFIG"
    stop_all
    ;;
  *) die "unknown command: $COMMAND" ;;
esac
