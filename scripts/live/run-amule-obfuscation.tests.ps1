$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'run-amule-obfuscation.ps1'
$source = Get-Content -Raw -LiteralPath $scriptPath

function Require-Match([string]$Pattern, [string]$Description) {
    $match = [regex]::Match($source, $Pattern)
    if (-not $match.Success) { throw "missing $Description" }
    return $match.Index
}

$daemonReady = Require-Match '\$readyDeadline\s*=.*AddSeconds\(30\)' 'daemon readiness stage'
$listenerReady = Require-Match '\$listenerReadyDeadline\s*=.*AddSeconds\(15\)' 'listener readiness stage'
$addLink = Require-Match ([regex]::Escape("Invoke-AmuleCmd ('Add ' + `$uploadLink)")) 'amulecmd source-link injection'

if (-not ($daemonReady -lt $listenerReady -and $listenerReady -lt $addLink)) {
    throw 'expected daemon ready -> listener ready -> amulecmd Add ordering'
}
if ($source -match '\$daemonLinkArgument|amuled[^\r\n]*\$uploadLink') {
    throw 'source link must not be passed on the amuled command line'
}

Write-Output 'aMule harness ordering test passed'
