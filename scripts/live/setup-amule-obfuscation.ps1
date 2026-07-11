[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$stateRoot = Join-Path $repoRoot '.tmp_live_amule_obfuscation'
$templatePath = Join-Path $PSScriptRoot 'amule-obfuscation.conf.in'
$toolCandidates = @(
    (Join-Path $repoRoot 'build/default/Debug/ed2k-tool.exe'),
    (Join-Path $repoRoot 'build/default-release/Release/ed2k-tool.exe')
)
$hashTool = $toolCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

function Invoke-WslText([string]$Command) {
    $output = & wsl.exe -e bash -lc $Command 2>$null
    if ($LASTEXITCODE -ne 0) { throw ($output -join [Environment]::NewLine) }
    return ($output -join "`n").Trim()
}

function Convert-ToWslPath([string]$Path) {
    if ($Path.Contains("'")) { throw "Paths containing apostrophes are not supported: $Path" }
    return Invoke-WslText "wslpath -a '$Path'"
}

function Write-DeterministicFile([string]$Path, [int]$Size, [int]$Seed) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write,
                             [IO.FileShare]::None)
    try {
        $buffer = New-Object byte[] 8192
        $offset = 0
        while ($offset -lt $Size) {
            $count = [Math]::Min($buffer.Length, $Size - $offset)
            for ($i = 0; $i -lt $count; ++$i) {
                $buffer[$i] = [byte]((($offset + $i) * 73 + $Seed) -band 0xff)
            }
            $stream.Write($buffer, 0, $count)
            $offset += $count
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-RedLink([string]$Path, [string]$Name) {
    $output = & $hashTool hash $Path --red 2>&1
    if ($LASTEXITCODE -ne 0) { throw "ed2k-tool hash failed: $($output -join ' ')" }
    $match = [regex]::Match(($output -join "`n"), '\|([0-9a-fA-F]{32})\|/')
    if (-not $match.Success) { throw "Could not parse Red eD2k hash from ed2k-tool output" }
    $hash = $match.Groups[1].Value.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $Path).Length
    return [pscustomobject]@{ Hash = $hash; Link = "ed2k://|file|$Name|$size|$hash|/" }
}

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL is required. Install/enable WSL, then rerun this setup script.'
}
$amuledCheck = & wsl.exe -e bash -lc 'test -x /usr/bin/amuled' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw 'aMule is missing in WSL. Install manually: sudo apt-get install amule-daemon amule-utils'
}
$amuled = (& wsl.exe -e bash -lc '/usr/bin/amuled --version 2>&1 || true' 2>$null | Out-String).Trim()
$amulecmdCheck = & wsl.exe -e bash -lc 'test -x /usr/bin/amulecmd' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw 'amulecmd is missing in WSL. Install manually: sudo apt-get install amule-utils'
}
if (-not $hashTool) {
    throw 'ed2k-tool.exe is missing. Build it first: cmake --build --preset default --target ed2k-tool'
}
if (-not (Test-Path -LiteralPath $templatePath)) { throw "Missing template: $templatePath" }

if (Test-Path -LiteralPath $stateRoot) { Remove-Item -LiteralPath $stateRoot -Recurse -Force }
New-Item -ItemType Directory -Path $stateRoot | Out-Null

$fixtureName = 'live-obfuscation-fixture.bin'
$fixtureSize = 393217 # More than two 180 KiB AICH blocks.
$fixturePath = Join-Path $stateRoot $fixtureName
Write-DeterministicFile $fixturePath $fixtureSize 19
$fixture = Get-RedLink $fixturePath $fixtureName
Set-Content -LiteralPath (Join-Path $stateRoot 'fixture.hash') -Value $fixture.Hash -NoNewline
Set-Content -LiteralPath (Join-Path $stateRoot 'fixture.link') -Value $fixture.Link -NoNewline

$uploadName = 'live-obfuscation-upload-evidence.bin'
$uploadPath = Join-Path $stateRoot $uploadName
Write-DeterministicFile $uploadPath 19456000 47 # Exactly two eD2k parts, matching aMule handoff behavior.
$upload = Get-RedLink $uploadPath $uploadName
Set-Content -LiteralPath (Join-Path $stateRoot 'upload.hash') -Value $upload.Hash -NoNewline
Set-Content -LiteralPath (Join-Path $stateRoot 'upload.link') -Value $upload.Link -NoNewline

$template = Get-Content -LiteralPath $templatePath -Raw
$modes = @(
    @{ Name = 'required'; Tcp = 24662; Udp = 24672; Ec = 24712; Upload = 24862; Required = 1 },
    @{ Name = 'optional'; Tcp = 25662; Udp = 25672; Ec = 25712; Upload = 25862; Required = 0 }
)
$identity = [byte[]](0x14, 0x4d, 0x75, 0x6c, 0x65, 0x2d, 0x0e, 0x62, 0x66,
                     0x75, 0x73, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e)
$userHash = (($identity[1..16] | ForEach-Object { $_.ToString('x2') }) -join '')

foreach ($mode in $modes) {
    $modeRoot = Join-Path $stateRoot $mode.Name
    $configDir = Join-Path $modeRoot 'config'
    $incomingDir = Join-Path $modeRoot 'incoming'
    $tempDir = Join-Path $modeRoot 'temp'
    New-Item -ItemType Directory -Path $configDir, $incomingDir, $tempDir | Out-Null
    Copy-Item -LiteralPath $fixturePath -Destination (Join-Path $incomingDir $fixtureName)
    [IO.File]::WriteAllBytes((Join-Path $configDir 'preferences.dat'), $identity)
    Set-Content -LiteralPath (Join-Path $modeRoot 'user-hash.txt') -Value $userHash -NoNewline

    $config = $template.Replace('@MODE@', $mode.Name)
    $config = $config.Replace('@TCP_PORT@', [string]$mode.Tcp)
    $config = $config.Replace('@UDP_PORT@', [string]$mode.Udp)
    $config = $config.Replace('@EC_PORT@', [string]$mode.Ec)
    $config = $config.Replace('@CRYPT_REQUIRED@', [string]$mode.Required)
    $config = $config.Replace('@CONFIG_DIR@', (Convert-ToWslPath $configDir))
    $config = $config.Replace('@INCOMING_DIR@', (Convert-ToWslPath $incomingDir))
    $config = $config.Replace('@TEMP_DIR@', (Convert-ToWslPath $tempDir))
    Set-Content -LiteralPath (Join-Path $configDir 'amule.conf') -Value $config -NoNewline

    @(
        "MODE=$($mode.Name)", "TCP_PORT=$($mode.Tcp)", "UDP_PORT=$($mode.Udp)",
        "EC_PORT=$($mode.Ec)", "UPLOAD_PORT=$($mode.Upload)"
    ) | Set-Content -LiteralPath (Join-Path $modeRoot 'ports.env')
}

Write-Host "aMule: $amuled"
Write-Host "Fixture: $fixtureSize bytes, Red hash $($fixture.Hash)"
Write-Host "Link: $($fixture.Link)"
Write-Host "aMule user hash: $userHash"
Write-Host "State: $stateRoot"
