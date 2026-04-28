#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVTUNNEL_EXE="$ROOT_DIR/devtunnel.exe"
TUNNEL_ID="firewall-guard.inc1"
TUNNEL_NAME_PREFIX="cdkvj82q"
TUNNEL_REGION_SUFFIX="inc1.devtunnels.ms"
RUNTIME_TUNNEL_CONFIG="$ROOT_DIR/extension_tunnel/runtime_tunnel_config.local.json"
ADVANCED_BACKEND_PORT="${ADVANCED_BACKEND_PORT:-3100}"

SERVICE_START_DELAY="${SERVICE_START_DELAY:-8}"
LOCAL_READY_TIMEOUT="${LOCAL_READY_TIMEOUT:-90}"
TUNNEL_READY_TIMEOUT="${TUNNEL_READY_TIMEOUT:-120}"
TUNNEL_PORTS=("$ADVANCED_BACKEND_PORT" 5000 6000 7000)

to_windows_path() {
    local path="$1"
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -aw "$path"
    elif command -v wslpath >/dev/null 2>&1; then
        wslpath -w "$path"
    else
        printf '%s\n' "$path"
    fi
}

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 1
    fi
}

tunnel_url_for_port() {
    local port="$1"
    printf 'https://%s-%s.%s/' "$TUNNEL_NAME_PREFIX" "$port" "$TUNNEL_REGION_SUFFIX"
}

local_status_url_for_port() {
    local port="$1"
    printf 'http://localhost:%s/api/status' "$port"
}

public_status_url_for_port() {
    local port="$1"
    printf '%sapi/status' "$(tunnel_url_for_port "$port")"
}

ensure_devtunnel() {
    if [[ ! -f "$DEVTUNNEL_EXE" ]]; then
        printf 'Downloading devtunnel.exe...\n'
        powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
            "Invoke-WebRequest https://aka.ms/TunnelsCliDownload/win-x64 -OutFile '$(to_windows_path "$DEVTUNNEL_EXE")'"
    fi
}

login_devtunnel() {
    printf 'Logging into Dev Tunnel with GitHub...\n'
    "$DEVTUNNEL_EXE" user login --github --use-browser-auth
}

ensure_ports() {
    local port
    local output

    printf 'Ensuring tunnel ports exist...\n'
    for port in "${TUNNEL_PORTS[@]}"; do
        printf '  Port %s\n' "$port"
        output="$("$DEVTUNNEL_EXE" port create "$TUNNEL_ID" -p "$port" --protocol http 2>&1 || true)"
        if [[ "$output" == *"Port Number"* ]] || [[ "$output" == *"already"* ]] || [[ -z "$output" ]]; then
            continue
        fi
    done
}

start_services() {
    printf 'Starting firewall services with start_firewall.bat option 8 (search disabled)...\n'
    cmd.exe //c start "Firewall Start All" /D "$(to_windows_path "$ROOT_DIR")" cmd /c "set FIREWALL_ADVANCED_PORT=$ADVANCED_BACKEND_PORT && set FIREWALL_SKIP_SEARCH=1 && echo 8|start_firewall.bat"
}

wait_for_local_services() {
    local timeout_ms=$((LOCAL_READY_TIMEOUT * 1000))

    printf 'Waiting for local services to answer...\n'
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {
param([int]\$TimeoutMs)
\$targets = @(
    @{ Label = '$ADVANCED_BACKEND_PORT'; Uri = 'http://localhost:$ADVANCED_BACKEND_PORT/api/status' },
    @{ Label = '5000'; Uri = 'http://localhost:5000/api/status' },
    @{ Label = '6000'; Uri = 'http://localhost:6000/api/status' },
    @{ Label = '7000'; Uri = 'http://localhost:7000/api/status' }
)
\$deadline = (Get-Date).AddMilliseconds(\$TimeoutMs)
foreach (\$target in \$targets) {
    \$ready = \$false
    while ((Get-Date) -lt \$deadline) {
        try {
            \$response = Invoke-WebRequest -UseBasicParsing -Uri \$target.Uri -TimeoutSec 5
            if (\$response.StatusCode -ge 200 -and \$response.StatusCode -lt 500) {
                Write-Output ('Local port ' + \$target.Label + ' ready')
                \$ready = \$true
                break
            }
        } catch {}
        Start-Sleep -Seconds 2
    }

    if (-not \$ready) {
        throw ('Local port ' + \$target.Label + ' did not become ready in time.')
    }
}
}" "$timeout_ms"
}

start_tunnel() {
    local root_win
    local devtunnel_win

    root_win="$(to_windows_path "$ROOT_DIR")"
    devtunnel_win="$(to_windows_path "$DEVTUNNEL_EXE")"

    printf 'Starting Dev Tunnel host...\n'
    cmd.exe //c start "Firewall Dev Tunnel" /D "$root_win" cmd /k "\"$devtunnel_win\" host $TUNNEL_ID -p $ADVANCED_BACKEND_PORT 5000 6000 7000 --protocol http --allow-anonymous"
}

wait_for_tunnel_urls() {
    local timeout_ms=$((TUNNEL_READY_TIMEOUT * 1000))

    printf 'Waiting for public tunnel URLs to stop returning 502...\n'
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {
param([int]\$TimeoutMs)
\$headers = @{ 'X-Tunnel-Skip-AntiPhishing-Page' = 'true' }
\$targets = @(
    @{ Label = '$ADVANCED_BACKEND_PORT'; Uri = 'https://cdkvj82q-$ADVANCED_BACKEND_PORT.inc1.devtunnels.ms/api/status' },
    @{ Label = '5000'; Uri = 'https://cdkvj82q-5000.inc1.devtunnels.ms/api/status' },
    @{ Label = '6000'; Uri = 'https://cdkvj82q-6000.inc1.devtunnels.ms/api/status' }
)
\$deadline = (Get-Date).AddMilliseconds(\$TimeoutMs)
foreach (\$target in \$targets) {
    \$ready = \$false
    while ((Get-Date) -lt \$deadline) {
        try {
            \$response = Invoke-WebRequest -UseBasicParsing -Uri \$target.Uri -Headers \$headers -TimeoutSec 10
            if (\$response.StatusCode -ge 200 -and \$response.StatusCode -lt 500 -and \$response.StatusCode -ne 502) {
                Write-Output ('Public port ' + \$target.Label + ' ready')
                \$ready = \$true
                break
            }
        } catch {
            \$statusCode = \$null
            if (\$_.Exception.Response -and \$_.Exception.Response.StatusCode) {
                \$statusCode = [int]\$_.Exception.Response.StatusCode
            }
            if (\$statusCode -and \$statusCode -ne 502) {
                Write-Output ('Public port ' + \$target.Label + ' reachable with HTTP ' + \$statusCode)
                \$ready = \$true
                break
            }
        }
        Start-Sleep -Seconds 2
    }

    if (-not \$ready) {
        throw ('Public port ' + \$target.Label + ' stayed unavailable/502.')
    }
}
}" "$timeout_ms"
}

write_runtime_tunnel_config() {
    local output_win
    local output_win_escaped
    local tunnel_id_escaped
    output_win="$(to_windows_path "$RUNTIME_TUNNEL_CONFIG")"
    output_win_escaped="${output_win//\'/\'\'}"
    tunnel_id_escaped="${TUNNEL_ID//\'/\'\'}"

    printf 'Writing runtime tunnel config...\n'
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {
\$OutputPath = '$output_win_escaped'
\$TunnelId = '$tunnel_id_escaped'
\$config = [ordered]@{
    advancedBackendBase = 'https://cdkvj82q-$ADVANCED_BACKEND_PORT.inc1.devtunnels.ms/'
    backendBase = 'https://cdkvj82q-5000.inc1.devtunnels.ms/'
    backendApiBase = 'https://cdkvj82q-5000.inc1.devtunnels.ms/api'
    localEngineBase = 'http://localhost:7000/'
    localEngineApiBase = 'http://localhost:7000/api'
    extensionServerBase = 'https://cdkvj82q-6000.inc1.devtunnels.ms/'
    tunnelId = \$TunnelId
    updatedAt = (Get-Date).ToString('o')
}
\$directory = Split-Path -Parent \$OutputPath
if (\$directory -and -not (Test-Path \$directory)) {
    New-Item -ItemType Directory -Path \$directory | Out-Null
}
\$config | ConvertTo-Json | Set-Content -Path \$OutputPath -Encoding UTF8
Write-Output ('Runtime config updated: ' + \$OutputPath)
}"
}

invoke_urls() {
    local url
    local urls=(
        "$(tunnel_url_for_port "$ADVANCED_BACKEND_PORT")"
        "$(tunnel_url_for_port 5000)"
        "$(tunnel_url_for_port 6000)"
        "$(tunnel_url_for_port 7000)"
    )

    printf 'Invoking and opening tunnel URLs...\n'
    for url in "${urls[@]}"; do
        printf '  %s\n' "$url"
        curl -s -H "X-Tunnel-Skip-AntiPhishing-Page: true" "$url" > /dev/null || true
        powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process '$url'"
    done
}

require_command powershell.exe
require_command cmd.exe
require_command curl

ensure_devtunnel
login_devtunnel
ensure_ports
start_services
sleep "$SERVICE_START_DELAY"
wait_for_local_services
start_tunnel
wait_for_tunnel_urls
printf 'Public port 7000 will use localhost fallback for the UI.\n'
write_runtime_tunnel_config

printf '==================================\n'
printf 'DONE\n'
printf '==================================\n'

invoke_urls
