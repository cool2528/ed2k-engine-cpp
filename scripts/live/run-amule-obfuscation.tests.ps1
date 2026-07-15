$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'run-amule-obfuscation.ps1'
$source = Get-Content -Raw -LiteralPath $scriptPath

function Require-Match([string]$Pattern, [string]$Description) {
    $match = [regex]::Match($source, $Pattern)
    if (-not $match.Success) { throw "missing $Description" }
    return $match.Index
}

$stubReady = Require-Match '\$stubReadyDeadline\s*=.*AddSeconds\(15\)' 'login stub readiness stage'
$daemonReady = Require-Match '\$readyDeadline\s*=.*AddSeconds\(30\)' 'daemon readiness stage'
$listenerReady = Require-Match '\$listenerReadyDeadline\s*=.*AddSeconds\(15\)' 'listener readiness stage'
$stubConnect = Require-Match ([regex]::Escape('Invoke-AmuleCmd "Connect $peerIp`:$stubPort"')) 'stub server connect command'
$addLink = Require-Match ([regex]::Escape("Invoke-AmuleCmd ('Add ' + `$uploadLink)")) 'amulecmd source-link injection'
$sourceCheck = Require-Match 'Total sources:' 'post-Add source registration verification'

if (-not ($stubReady -lt $daemonReady -and $daemonReady -lt $listenerReady -and
          $listenerReady -lt $stubConnect -and $stubConnect -lt $addLink -and $addLink -lt $sourceCheck)) {
    throw 'expected stub ready -> daemon ready -> listener ready -> stub connect -> amulecmd Add -> source verification ordering'
}
if ($source -match 'hostname -I') {
    throw 'peer address must come from the eth0 global address, not unstable hostname -I ordering'
}
Require-Match 'ip -4 -o addr show dev eth0 scope global' 'deterministic WSL eth0 peer address derivation' | Out-Null
if ($source -match '\$daemonLinkArgument|amuled[^\r\n]*\$uploadLink') {
    throw 'source link must not be passed on the amuled command line'
}
if ($source -match 'Get-NetTCPConnection') {
    throw 'TCP port preflight must not depend on the potentially blocking Get-NetTCPConnection cmdlet'
}
if ($source -notmatch 'TcpListener.*IPAddress.*Any') {
    throw 'TCP port preflight must use a bounded local bind probe'
}
Write-Output 'aMule harness ordering test passed'
