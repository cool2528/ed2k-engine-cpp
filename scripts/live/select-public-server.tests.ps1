$ErrorActionPreference = 'Stop'

$selector = Join-Path $PSScriptRoot 'select-public-server.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ed2k-selector-test-" + [guid]::NewGuid())
$listener = $null

try {
    New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
    $mockTool = Join-Path $testRoot 'mock-ed2k-tool.ps1'
    @'
param(
    [Parameter(Position = 0)][string]$Command,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
if ($Command -eq 'update-serverlist') {
    Set-Content -LiteralPath $Rest[1] -Value 'mock server.met'
    Write-Output "updated $($Rest[1])"
    exit 0
}
if ($Command -eq 'serverlist') {
    Write-Output 'IP                     PORT   MAXUSER  NAME'
    Write-Output '127.0.0.1              1      0        stale-1'
    Write-Output '127.0.0.1              2      0        stale-2'
    Write-Output '127.0.0.1              3      0        stale-3'
    Write-Output '(3 servers)'
    exit 0
}
exit 2
'@ | Set-Content -LiteralPath $mockTool -Encoding utf8

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $fallbackPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $outputDirectory = Join-Path $testRoot 'output'
    $selected = & $selector `
        -ServerListUrl 'https://example.invalid/server.met' `
        -ToolPath $mockTool `
        -OutputDirectory $outputDirectory `
        -ConnectTimeoutMs 100 `
        -FallbackEndpoints @("127.0.0.1:$fallbackPort") |
        Select-Object -Last 1

    if ($selected -ne "127.0.0.1:$fallbackPort") {
        throw "expected reachable fallback endpoint, got '$selected'"
    }
    $selection = Get-Content -Raw -LiteralPath (Join-Path $outputDirectory 'server-selection.txt')
    if ($selection -notmatch '(?m)^attempts=4\r?$') {
        throw "expected three retrieved attempts plus one fallback within the total bound:`n$selection"
    }
    if ($selection -notmatch '(?m)^candidate_source=downloaded \+ static fallback\r?$') {
        throw "expected downloaded-plus-fallback source evidence:`n$selection"
    }

    $repeatOutputDirectory = Join-Path $testRoot 'repeat-output'
    $repeatSelected = & $selector `
        -ServerListUrl 'https://example.invalid/server.met' `
        -ToolPath $mockTool `
        -OutputDirectory $repeatOutputDirectory `
        -ConnectTimeoutMs 100 `
        -FallbackEndpoints @("127.0.0.1:$fallbackPort") |
        Select-Object -Last 1
    $repeatSelection = Get-Content -Raw -LiteralPath (Join-Path $repeatOutputDirectory 'server-selection.txt')
    $attemptPattern = '(?m)^127\.0\.0\.1:\d+ (?:unreachable|reachable)\r?$'
    $firstOrder = [regex]::Matches($selection, $attemptPattern).Value -join "`n"
    $repeatOrder = [regex]::Matches($repeatSelection, $attemptPattern).Value -join "`n"
    if ($repeatSelected -ne $selected -or $repeatOrder -ne $firstOrder) {
        throw "expected deterministic daily candidate order across repeated runs"
    }

    $boundedOutputDirectory = Join-Path $testRoot 'bounded-output'
    $boundedFailed = $false
    try {
        & $selector `
            -ServerListUrl 'https://example.invalid/server.met' `
            -ToolPath $mockTool `
            -OutputDirectory $boundedOutputDirectory `
            -ConnectTimeoutMs 100 `
            -FallbackEndpoints @('127.0.0.1:4', '127.0.0.1:5') | Out-Null
    }
    catch {
        $boundedFailed = $true
    }
    if (-not $boundedFailed) {
        throw 'expected all-unreachable selector run to fail'
    }
    $boundedSelection = Get-Content -Raw -LiteralPath (Join-Path $boundedOutputDirectory 'server-selection.txt')
    if ($boundedSelection -notmatch '(?m)^attempts=5\r?$') {
        throw "expected selector to stop at five total attempts:`n$boundedSelection"
    }
    Write-Output 'selector stale-list fallback test passed'
}
finally {
    if ($listener) { $listener.Stop() }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
