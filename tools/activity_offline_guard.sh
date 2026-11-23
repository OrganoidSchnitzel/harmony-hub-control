#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PLUGIN="$REPO_ROOT/payload/activity/codexactivity.lua"
WEBUI="$REPO_ROOT/payload/source/codex_webui.c"
NETSTART="$REPO_ROOT/payload/scripts/netservicestarter.lua"
EGRESS="$REPO_ROOT/payload/scripts/offline_egress_guard.sh"
INIT="$REPO_ROOT/payload/scripts/init.sh"

test -f "$PLUGIN"
test -f "$NETSTART"
test -f "$EGRESS"

for required in \
  'cloud_blocker.conf' \
  'core.resourcemanager' \
  'saveResource' \
  'config_new' \
  'FunctionList' \
  'configVersion' \
  'connect.stateDigest?notify'
do
  rg -F "$required" "$PLUGIN" >/dev/null
done

for forbidden in \
  'require("socket")' \
  'core.session' \
  'makeRequest' \
  'offlinequeue' \
  'proxy.resource' \
  'syncremotechanges' \
  'myharmony' \
  'logitech.com' \
  'https://'
do
  if rg -F "$forbidden" "$PLUGIN" >/dev/null; then
    echo "offline activity plugin contains forbidden path: $forbidden" >&2
    exit 1
  fi
done

# HTTP client libraries and shell-outs: the plugin itself must never open a
# connection. Regexes so spacing/quoting variants of require() are caught too.
for forbidden in \
  'require\s*\(?\s*["'"'"'](socket|ssl|http|https|ltn12|luasocket|curl)\b' \
  '\bsocket\.(http|tcp|udp|connect|dns)\b' \
  '\bssl\.https\b' \
  '\bhttp\.request\b' \
  '\b(curl|wget)\b'
do
  if rg -e "$forbidden" "$PLUGIN" >/dev/null; then
    echo "offline activity plugin contains forbidden network call: $forbidden" >&2
    exit 1
  fi
done

# Plain http:// is allowed only in the Home Assistant webhook handling: the
# plugin validates and stores webhook URLs that the Harmony engine calls, it
# never fetches them itself. Every http:// occurrence must be one of these
# exact fixed strings; anything else (a new URL, a new host) fails the guard.
check_http_allowlist() {
  awk '
    function strip(s, lit,   i, out) {
      out = ""
      while ((i = index(s, lit)) > 0) {
        out = out substr(s, 1, i - 1)
        s = substr(s, i + length(lit))
      }
      return out s
    }
    index($0, "http://") {
      line = $0
      line = strip(line, "\"^http://([^/]+)(/.*)$\"")
      line = strip(line, "\"webhook must be a plain http:// URL the hub can reach\"")
      line = strip(line, "\"http://127.0.0.1:8080/api/bt-webhook\"")
      if (index(line, "http://")) {
        printf "%s:%d: %s\n", FILENAME, FNR, $0
        bad = 1
      }
    }
    END { exit bad }
  ' "$1"
}
if ! check_http_allowlist "$PLUGIN" >&2; then
  echo "offline activity plugin contains forbidden path: http:// outside the webhook allowlist" >&2
  exit 1
fi

for forbidden in \
  'proxy.resource?put' \
  'setup.syncremotechanges' \
  '"forceUpdate"'
do
  if rg -F "$forbidden" "$WEBUI" >/dev/null; then
    echo "activity web API contains forbidden firmware sync path: $forbidden" >&2
    exit 1
  fi
done

for required in \
  'codex offline HBus guards registered' \
  '"proxy.resource?get"' \
  '"proxy.resource?put"' \
  '"setup.sync"' \
  '"setup.syncremotechanges"' \
  'acknowledged resource put without cloud' \
  'served local resource'
do
  rg -F "$required" "$NETSTART" >/dev/null
done

for required in \
  'cloud_blocker.conf' \
  'route del default' \
  '224.0.0.0' \
  '240.0.0.0'
do
  rg -F "$required" "$EGRESS" >/dev/null
done

rg -F 'PAYLOAD / "activity" / "codexactivity.lua"' "$REPO_ROOT/install_webui.py" >/dev/null

# Installer-path assertion (stale-guard repair): the RECOVERY installer must
# reference the exact `activity/codexactivity.lua` candidate. Accept either the
# Windows backslash separator or the portable forward-slash separator for that
# same candidate; still require the exact activity Lua basename/path. A narrow
# two-alternative fixed-string check is used (no broad regex), so a wrong or
# missing path cannot satisfy it.
if ! rg -F -e 'activity\codexactivity.lua' -e 'activity/codexactivity.lua' \
    "$REPO_ROOT/install_webui.ps1" >/dev/null; then
  echo "install_webui.ps1 does not reference the activity/codexactivity.lua candidate" >&2
  exit 1
fi

# Regression self-check: the same two-alternative pattern must accept the
# forward-slash candidate and must reject a wrong activity path. This proves
# the assertion is not a vacuous pass.
_guard_tmp=$(mktemp -d)
trap 'rm -rf "$_guard_tmp"' EXIT
printf 'activity/codexactivity.lua\n' > "$_guard_tmp/fwd"
printf 'activity\\codexactivity.lua\n' > "$_guard_tmp/back"
printf 'activity/codexmqtt.lua\n' > "$_guard_tmp/wrong"
rg -F -e 'activity\codexactivity.lua' -e 'activity/codexactivity.lua' "$_guard_tmp/fwd" >/dev/null
rg -F -e 'activity\codexactivity.lua' -e 'activity/codexactivity.lua' "$_guard_tmp/back" >/dev/null
if rg -F -e 'activity\codexactivity.lua' -e 'activity/codexactivity.lua' "$_guard_tmp/wrong" >/dev/null; then
  echo "offline activity guard: wrong-path regression failed" >&2
  exit 1
fi

# Regression self-check for the http:// allowlist: the known webhook lines
# pass, an unlisted http:// URL (even next to an allowed one) fails.
cat > "$_guard_tmp/http_ok" <<'EOF'
  local host, path = string.match(type(value) == "string" and value or "", "^http://([^/]+)(/.*)$")
    return nil, "webhook must be a plain http:// URL the hub can reach"
local BT_WEBHOOK = "http://127.0.0.1:8080/api/bt-webhook"
EOF
printf 'local u = "http://example.com/x"\n' > "$_guard_tmp/http_bad"
printf 'local u = "http://127.0.0.1:8080/api/bt-webhook" .. "http://evil/"\n' > "$_guard_tmp/http_mixed"
if ! check_http_allowlist "$_guard_tmp/http_ok" >/dev/null; then
  echo "offline activity guard: http allowlist rejects the known webhook lines" >&2
  exit 1
fi
for _bad in http_bad http_mixed; do
  if check_http_allowlist "$_guard_tmp/$_bad" >/dev/null; then
    echo "offline activity guard: http allowlist regression failed ($_bad)" >&2
    exit 1
  fi
done

rg -F 'offline_egress_guard.sh monitor' "$INIT" >/dev/null
rg -F '"gatewayType":"codexactivity"' "$INIT" >/dev/null
rg -F 'offline_egress_guard.sh' "$REPO_ROOT/install_webui.py" >/dev/null
rg -F 'offline_egress_guard.sh' "$REPO_ROOT/install_webui.ps1" >/dev/null

echo "offline activity guard passed"
