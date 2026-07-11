[CmdletBinding()]
param(
    # Trusted, community-maintained list. Override for a different reviewed source.
    [string]$ServerListUrl = 'https://upd.emule-security.org/server.met',
    [string]$ToolPath = '',
    [string]$OutputDirectory = '.tmp_live_server_probe',
    [ValidateRange(100, 10000)]
    [int]$ConnectTimeoutMs = 2000
)

$ErrorActionPreference = 'Stop'
$DefaultServerListUrl = 'https://upd.emule-security.org/server.met'
$StaticFallback = @(
    '45.82.80.155:5687',
    '176.123.5.89:4725',
    '91.208.162.87:4232',
    '85.121.5.137:4232',
    '77.42.68.79:4232'
)

if ([string]::IsNullOrWhiteSpace($ServerListUrl)) {
    $ServerListUrl = $DefaultServerListUrl
}
if ([string]::IsNullOrWhiteSpace($ToolPath)) {
    $candidates = @(
        'build/default-release/Release/ed2k-tool.exe',
        'build/default/Debug/ed2k-tool.exe',
        'build/linux-release/ed2k-tool',
        'build/linux/ed2k-tool'
    )
    $ToolPath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($ToolPath) -or -not (Test-Path -LiteralPath $ToolPath -PathType Leaf)) {
    throw 'ed2k-tool was not found; build it or pass -ToolPath'
}

$ToolPath = (Resolve-Path -LiteralPath $ToolPath).Path
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$serverMet = Join-Path $OutputDirectory 'server.met'
$selectionLog = Join-Path $OutputDirectory 'server-selection.txt'
$downloadLog = Join-Path $OutputDirectory 'serverlist-download.log'

function Test-TcpEndpoint {
    param([Parameter(Mandatory)][string]$Ip, [Parameter(Mandatory)][int]$Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($Ip, $Port)
        if (-not $connect.Wait($ConnectTimeoutMs)) {
            return $false
        }
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

$retrieved = $false
& $ToolPath update-serverlist $ServerListUrl $serverMet 2>&1 |
    Tee-Object -FilePath $downloadLog | Write-Host
if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $serverMet -PathType Leaf)) {
    $retrieved = $true
}

$endpoints = [System.Collections.Generic.List[string]]::new()
if ($retrieved) {
    $parsed = & $ToolPath serverlist $serverMet 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "downloaded server.met could not be parsed by ed2k-tool: $($parsed -join ' ')"
    }
    foreach ($line in $parsed) {
        if ($line -match '^\s*(?<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?<port>\d{1,5})\s+') {
            $endpoint = "$($Matches.ip):$($Matches.port)"
            if (-not $endpoints.Contains($endpoint)) {
                $endpoints.Add($endpoint)
            }
        }
    }
    if ($endpoints.Count -eq 0) {
        throw 'downloaded server.met contained no candidates recognized by ed2k-tool'
    }
}
else {
    Write-Warning 'server-list retrieval failed; using the project-maintained static fallback endpoints'
    foreach ($endpoint in $StaticFallback) {
        $endpoints.Add($endpoint)
    }
}

$attempts = [System.Collections.Generic.List[string]]::new()
$selected = $null
foreach ($endpoint in ($endpoints | Select-Object -First 5)) {
    $parts = $endpoint.Split(':')
    $reachable = Test-TcpEndpoint -Ip $parts[0] -Port ([int]$parts[1])
    $status = if ($reachable) { 'reachable' } else { 'unreachable' }
    $attempts.Add("$endpoint $status")
    Write-Host "TCP probe $endpoint`: $status"
    if ($reachable) {
        $selected = $endpoint
        break
    }
}

$source = if ($retrieved) { "downloaded $ServerListUrl" } else { 'static fallback after retrieval failure' }
@(
    "source=$source"
    "tool=$ToolPath"
    "connect_timeout_ms=$ConnectTimeoutMs"
    "attempts=$($attempts.Count)"
    $attempts
    "selected=$selected"
) | Set-Content -LiteralPath $selectionLog -Encoding utf8

if ([string]::IsNullOrWhiteSpace($selected)) {
    throw "no reachable eD2k server found in $($attempts.Count) bounded TCP attempts; see $selectionLog"
}
if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
    "server=$selected" | Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8
}
Write-Output $selected
