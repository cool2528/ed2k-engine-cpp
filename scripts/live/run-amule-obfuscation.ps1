[CmdletBinding()]
param(
    [ValidateSet('required', 'optional')]
    [string]$Mode = 'required',
    [string]$TestExe,
    [ValidateSet('', 'after-upload-start')]
    [string]$FailureInjection = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$stateRoot = Join-Path $repoRoot '.tmp_live_amule_obfuscation'
$modeRoot = Join-Path $stateRoot $Mode
$configDir = Join-Path $modeRoot 'config'
$logsDir = Join-Path $modeRoot 'logs'
$ecPassword = 'ed2k-live'
$daemonPid = $null
$wslProcess = $null
$uploadProcess = $null
$uploadPid = $null
$succeeded = $false
$testInWsl = $false
$linuxConfig = $null

function Fail-Setup([string]$Message) {
    throw "$Message`nRun: ./scripts/live/setup-amule-obfuscation.ps1"
}

function Invoke-WslText([string]$Command, [switch]$AllowFailure) {
    $output = & wsl.exe -e bash -lc $Command 2>$null
    $code = $LASTEXITCODE
    if (-not $AllowFailure -and $code -ne 0) { throw ($output -join [Environment]::NewLine) }
    return [pscustomobject]@{ ExitCode = $code; Text = ($output -join "`n").Trim() }
}

function Bash-Quote([string]$Text) {
    if ($Text.Contains("'")) { throw "Values containing apostrophes are not supported: $Text" }
    return "'" + $Text + "'"
}
function Convert-ToWslPath([string]$Path) {
    return (Invoke-WslText "wslpath -a $(Bash-Quote $Path)").Text
}

function Read-EnvFile([string]$Path) {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^([^=]+)=(.*)$') { $values[$matches[1]] = $matches[2] }
    }
    return $values
}

function Test-TcpPortFree([int]$Port) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, $Port)
    try {
        $listener.Start()
    } catch [Net.Sockets.SocketException] {
        return $false
    } finally {
        $listener.Stop()
    }
    $probe = Invoke-WslText "! ss -ltnH | awk '{print `$4}' | grep -Eq '(^|:)$Port`$'" -AllowFailure
    return $probe.ExitCode -eq 0
}

function Test-UdpPortFree([int]$Port) {
    $probe = Invoke-WslText "! ss -lunH | awk '{print `$5}' | grep -Eq '(^|:)$Port`$'" -AllowFailure
    return $probe.ExitCode -eq 0
}

function Invoke-AmuleCmd([string]$Command, [switch]$AllowFailure) {
    $cmd = "/usr/bin/amulecmd -h 127.0.0.1 -p $ecPort -P $(Bash-Quote $ecPassword) -c $(Bash-Quote $Command)"
    $result = Invoke-WslText $cmd -AllowFailure:$AllowFailure
    Add-Content -LiteralPath (Join-Path $logsDir 'amulecmd.log') -Value "> $Command`n$($result.Text)"
    return $result
}

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { Fail-Setup 'WSL is unavailable.' }
$prereq = Invoke-WslText 'test -x /usr/bin/amuled && test -x /usr/bin/amulecmd' -AllowFailure
if ($prereq.ExitCode -ne 0) {
    throw 'aMule is missing in WSL. Install manually: sudo apt-get install amule-daemon amule-utils'
}

$requiredFiles = @(
    (Join-Path $configDir 'amule.conf'), (Join-Path $configDir 'preferences.dat'),
    (Join-Path $modeRoot 'ports.env'), (Join-Path $modeRoot 'user-hash.txt'),
    (Join-Path $stateRoot 'fixture.link'), (Join-Path $stateRoot 'fixture.hash'),
    (Join-Path $stateRoot 'live-obfuscation-fixture.bin'),
    (Join-Path $stateRoot 'upload.link'), (Join-Path $stateRoot 'upload.hash'),
    (Join-Path $stateRoot 'live-obfuscation-upload-evidence.bin')
)
foreach ($file in $requiredFiles) { if (-not (Test-Path -LiteralPath $file)) { Fail-Setup "Missing generated state: $file" } }

if (-not $TestExe) {
    $candidates = @(
        (Join-Path $repoRoot 'build/linux/ed2k_tests'),
        (Join-Path $repoRoot 'build/linux-release/ed2k_tests'),
        (Join-Path $repoRoot 'build/default/Debug/ed2k_tests.exe'),
        (Join-Path $repoRoot 'build/default-release/Release/ed2k_tests.exe')
    )
    $TestExe = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $TestExe -or -not (Test-Path -LiteralPath $TestExe)) {
    throw 'ed2k_tests.exe is missing. Build it first: cmake --build --preset default --target ed2k_tests'
}
$testInWsl = [IO.Path]::GetExtension($TestExe) -ne '.exe'
$linuxTestExe = if ($testInWsl) { Convert-ToWslPath $TestExe } else { $null }

$ports = Read-EnvFile (Join-Path $modeRoot 'ports.env')
$tcpPort = [int]$ports.TCP_PORT
$udpPort = [int]$ports.UDP_PORT
$ecPort = [int]$ports.EC_PORT
$uploadPort = [int]$ports.UPLOAD_PORT
foreach ($port in @($tcpPort, $ecPort, $uploadPort)) {
    if (-not (Test-TcpPortFree $port)) { throw "TCP port $port is already in use; refusing to disturb an existing service." }
}
if (-not (Test-UdpPortFree $udpPort)) { throw "UDP port $udpPort is already in use; refusing to disturb an existing service." }

if (Test-Path -LiteralPath $logsDir) { Remove-Item -LiteralPath $logsDir -Recurse -Force }
New-Item -ItemType Directory -Path $logsDir | Out-Null
$incomingDir = Join-Path $modeRoot 'incoming'
$tempDir = Join-Path $modeRoot 'temp'
Get-ChildItem -LiteralPath $incomingDir -File | Where-Object { $_.Name -ne 'live-obfuscation-fixture.bin' } | Remove-Item -Force
Get-ChildItem -LiteralPath $tempDir -Force | Remove-Item -Recurse -Force

if ($Mode -eq 'optional') {
    if (-not $testInWsl) {
        throw 'LiveUpload evidence requires the WSL test executable for the aMule partial-file handoff.'
    }
    $partialSource = Convert-ToWslPath (Join-Path $stateRoot 'live-obfuscation-upload-evidence.bin')
    $partialOut = Convert-ToWslPath (Join-Path $tempDir '001.part')
    $partialCommand = "ED2K_PARTIAL_SOURCE=$(Bash-Quote $partialSource) " +
                      "ED2K_PARTIAL_OUT=$(Bash-Quote $partialOut) " +
                      "$(Bash-Quote $linuxTestExe) --gtest_filter=LivePartMet.WritesEnginePartialFixture"
    $partialLog = Join-Path $logsDir 'live-partial-fixture.log'
    & wsl.exe -e bash -lc $partialCommand 2>$null | Tee-Object -FilePath $partialLog
    if ($LASTEXITCODE -ne 0) { throw "Could not stage aMule partial upload evidence (exit $LASTEXITCODE)." }
}

try {
  $linuxConfig = Convert-ToWslPath $configDir
  $peerIp = (Invoke-WslText "hostname -I | awk '{print `$1}'").Text
  if ($peerIp -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw "Could not determine the WSL peer address: '$peerIp'" }
  $uploadLink = $null
  if ($Mode -eq 'optional') {
      $uploadLink = (Get-Content -LiteralPath (Join-Path $stateRoot 'upload.link') -Raw).Trim()
      $uploadLink += "|sources,$peerIp`:$uploadPort|/"
  }
  $linuxPidFile = Convert-ToWslPath (Join-Path $logsDir 'amuled.pid')
  $launcherPath = Join-Path $logsDir 'launch-amuled.sh'
  $launcher = @(
    '#!/bin/bash',
    'umask 077',
    "echo `$`$ > $(Bash-Quote $linuxPidFile)",
    "exec /usr/bin/amuled -c $(Bash-Quote $linuxConfig) -o"
) -join "`n"
  Set-Content -LiteralPath $launcherPath -Value ($launcher + "`n") -NoNewline
  $linuxLauncher = Convert-ToWslPath $launcherPath
  $daemonOut = Join-Path $logsDir 'amuled.stdout.log'
  $daemonErr = Join-Path $logsDir 'amuled.stderr.log'

    $wslProcess = Start-Process -FilePath 'wsl.exe' -ArgumentList @('-e', 'bash', $linuxLauncher) `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput $daemonOut -RedirectStandardError $daemonErr

    $pidPath = Join-Path $logsDir 'amuled.pid'
    $pidDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $pidPath) -and [DateTime]::UtcNow -lt $pidDeadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $pidPath)) { throw 'amuled did not publish its Linux PID within 10 seconds.' }
    $daemonPid = [int](Get-Content -LiteralPath $pidPath -Raw).Trim()

    $ready = $false
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $readyDeadline) {
        if ($wslProcess.HasExited) { break }
        $identity = Invoke-WslText "tr '\0' ' ' </proc/$daemonPid/cmdline 2>/dev/null" -AllowFailure
        if ($identity.ExitCode -ne 0 -or $identity.Text -notmatch 'amuled' -or $identity.Text -notmatch [regex]::Escape($linuxConfig)) {
            throw "Recorded PID $daemonPid is not the isolated amuled process."
        }
        $client = New-Object Net.Sockets.TcpClient
        try {
            $connect = $client.ConnectAsync($peerIp, $tcpPort)
            $tcpReady = $connect.Wait(250) -and $client.Connected
        } catch { $tcpReady = $false } finally { $client.Dispose() }
        $ec = Invoke-AmuleCmd 'status' -AllowFailure
        if ($tcpReady -and $ec.ExitCode -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "amuled readiness timed out after 30 seconds. See $logsDir" }
    Write-Host 'aMule daemon ready.'

    if ($Mode -eq 'optional') {
        $uploadFile = Convert-ToWslPath (Join-Path $stateRoot 'live-obfuscation-upload-evidence.bin')
        $uploadOut = Join-Path $logsDir 'live-upload-test.stdout.log'
        $uploadErr = Join-Path $logsDir 'live-upload-test.stderr.log'
        $uploadLauncherPath = Join-Path $logsDir 'launch-upload-test.sh'
        $linuxUploadPidFile = Convert-ToWslPath (Join-Path $logsDir 'upload-test.pid')
        $uploadLauncher = @(
            '#!/bin/bash',
            "echo `$`$ > $(Bash-Quote $linuxUploadPidFile)",
            'export ED2K_LIVE=1',
            "export ED2K_UPLOAD_FILE=$(Bash-Quote $uploadFile)",
            "export ED2K_UPLOAD_PORT=$(Bash-Quote ([string]$uploadPort))",
            "exec $(Bash-Quote $linuxTestExe) --gtest_filter=LiveUpload.AcceptsLocalPeerUploadSession"
        ) -join "`n"
        Set-Content -LiteralPath $uploadLauncherPath -Value ($uploadLauncher + "`n") -NoNewline
        $linuxUploadLauncher = Convert-ToWslPath $uploadLauncherPath
        $uploadProcess = Start-Process -FilePath 'wsl.exe' -ArgumentList @('-e', 'bash', $linuxUploadLauncher) `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput $uploadOut -RedirectStandardError $uploadErr
        Start-Sleep -Seconds 1
        if ($uploadProcess.HasExited) { throw 'LiveUpload evidence test exited during local peer registration.' }
        $uploadPidPath = Join-Path $logsDir 'upload-test.pid'
        if (-not (Test-Path -LiteralPath $uploadPidPath)) { throw 'LiveUpload evidence test did not publish its Linux PID.' }
        $uploadPid = [int](Get-Content -LiteralPath $uploadPidPath -Raw).Trim()
        if ($FailureInjection -eq 'after-upload-start') {
            throw 'Injected failure after upload evidence process start.'
        }

        $listenerReady = $false
        $listenerReadyDeadline = [DateTime]::UtcNow.AddSeconds(15)
        while ([DateTime]::UtcNow -lt $listenerReadyDeadline) {
            if ($uploadProcess.HasExited) {
                throw 'LiveUpload evidence test exited before its listener became ready.'
            }
            $probe = Invoke-WslText "ss -ltnH | awk '{print `$4}' | grep -Eq '(^|:)$uploadPort`$'" -AllowFailure
            if ($probe.ExitCode -eq 0) {
                $listenerReady = $true
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $listenerReady) {
            throw "LiveUpload listener readiness timed out after 15 seconds on port $uploadPort."
        }
        Write-Host "LiveUpload listener ready on port $uploadPort."

        $addResult = Invoke-AmuleCmd ('Add ' + $uploadLink) -AllowFailure
        if ($addResult.ExitCode -ne 0) {
            throw "amulecmd Add failed after listener readiness: $($addResult.Text)"
        }
        Write-Host 'aMule source link injected through amulecmd Add.'
    }

    $fixtureLink = (Get-Content -LiteralPath (Join-Path $stateRoot 'fixture.link') -Raw).Trim()
    $fixtureHash = (Get-Content -LiteralPath (Join-Path $stateRoot 'fixture.hash') -Raw).Trim()
    $userHash = (Get-Content -LiteralPath (Join-Path $modeRoot 'user-hash.txt') -Raw).Trim()
    $env:ED2K_LIVE = '1'
    $env:ED2K_LIVE_OBFUSCATION = '1'
    $sourceIp = if ($testInWsl) { '127.0.0.1' } else { $peerIp }
    $env:ED2K_SOURCE = "$sourceIp`:$tcpPort"
    $env:ED2K_LINK = $fixtureLink
    $env:ED2K_EXPECT_MD4 = $fixtureHash
    $env:ED2K_AMULE_USER_HASH = $userHash
    $env:ED2K_AMULE_OBFUSCATION_MODE = $Mode

    if ($Mode -eq 'required') {
        $filter = 'LiveObfuscation.Configuration*:LiveObfuscation.Required*:LiveObfuscation.ConfigurationUserHashParserIsStrict'
    } else {
        $filter = 'LiveObfuscation.Configuration*:LiveObfuscation.Optional*:LiveObfuscation.ConfigurationUserHashParserIsStrict'
    }
    $task3Log = Join-Path $logsDir 'live-obfuscation-tests.log'
    if ($testInWsl) {
        $linuxXml = Convert-ToWslPath "$($task3Log).xml"
        $testCommand = @(
            "ED2K_LIVE=$(Bash-Quote $env:ED2K_LIVE)",
            "ED2K_LIVE_OBFUSCATION=$(Bash-Quote $env:ED2K_LIVE_OBFUSCATION)",
            "ED2K_SOURCE=$(Bash-Quote $env:ED2K_SOURCE)",
            "ED2K_LINK=$(Bash-Quote $env:ED2K_LINK)",
            "ED2K_EXPECT_MD4=$(Bash-Quote $env:ED2K_EXPECT_MD4)",
            "ED2K_AMULE_USER_HASH=$(Bash-Quote $env:ED2K_AMULE_USER_HASH)",
            "ED2K_AMULE_OBFUSCATION_MODE=$(Bash-Quote $env:ED2K_AMULE_OBFUSCATION_MODE)",
            (Bash-Quote $linuxTestExe),
            (Bash-Quote "--gtest_filter=$filter"),
            (Bash-Quote "--gtest_output=xml:$linuxXml")
        ) -join ' '
        & wsl.exe -e bash -lc $testCommand 2>$null | Tee-Object -FilePath $task3Log
    } else {
        & $TestExe "--gtest_filter=$filter" "--gtest_output=xml:$($task3Log).xml" 2>&1 | Tee-Object -FilePath $task3Log
    }
    if ($LASTEXITCODE -ne 0) { throw "Mode-specific LiveObfuscation tests failed with exit code $LASTEXITCODE." }

    if ($Mode -eq 'optional') {
        if (-not $uploadProcess.WaitForExit(150000)) {
            $uploadProcess.Kill()
            throw 'LiveUpload.AcceptsLocalPeerUploadSession exceeded its 150 second bound.'
        }
        Get-Content -LiteralPath $uploadOut | Tee-Object -FilePath (Join-Path $logsDir 'live-upload-test.log')
        if (Test-Path -LiteralPath $uploadErr) { Get-Content -LiteralPath $uploadErr | Add-Content -LiteralPath (Join-Path $logsDir 'live-upload-test.log') }
        if ($uploadProcess.ExitCode -ne 0) { throw "LiveUpload evidence failed with exit code $($uploadProcess.ExitCode)." }
    } else {
        Set-Content -LiteralPath (Join-Path $logsDir 'live-upload-test.log') -Value `
            'Not run in required mode: aMule cannot initiate obfuscation until it knows the engine user hash. Optional mode runs this evidence.'
    }

    $succeeded = $true
    Write-Host "Mode $Mode passed. Logs: $logsDir"
} finally {
    if ($daemonPid) {
        $identity = Invoke-WslText "tr '\0' ' ' </proc/$daemonPid/cmdline 2>/dev/null" -AllowFailure
        if ($identity.ExitCode -eq 0 -and $identity.Text -match 'amuled' -and
            $identity.Text -match [regex]::Escape($linuxConfig)) {
            Invoke-WslText "kill -TERM $daemonPid" -AllowFailure | Out-Null
            $stopDeadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                $alive = Invoke-WslText "kill -0 $daemonPid 2>/dev/null" -AllowFailure
                if ($alive.ExitCode -ne 0) { break }
                Start-Sleep -Milliseconds 200
            } while ([DateTime]::UtcNow -lt $stopDeadline)
            if ($alive.ExitCode -eq 0) { Write-Warning "Isolated amuled PID $daemonPid did not exit after SIGTERM." }
        } else {
            Write-Warning "PID $daemonPid no longer identifies this harness's amuled; it was not signalled."
        }
    }
    if ($wslProcess -and -not $wslProcess.HasExited) { $wslProcess.WaitForExit(5000) | Out-Null }
    if ($uploadPid) {
        $uploadAlive = Invoke-WslText "kill -0 $uploadPid 2>/dev/null" -AllowFailure
        if ($uploadAlive.ExitCode -eq 0) {
            $uploadIdentity = Invoke-WslText "tr '\0' ' ' </proc/$uploadPid/cmdline 2>/dev/null" -AllowFailure
            if ($uploadIdentity.ExitCode -eq 0 -and $uploadIdentity.Text -match 'ed2k_tests' -and
                $uploadIdentity.Text -match 'LiveUpload.AcceptsLocalPeerUploadSession') {
                Invoke-WslText "kill -TERM $uploadPid" -AllowFailure | Out-Null
                $uploadStopDeadline = [DateTime]::UtcNow.AddSeconds(5)
                do {
                    $uploadAlive = Invoke-WslText "kill -0 $uploadPid 2>/dev/null" -AllowFailure
                    if ($uploadAlive.ExitCode -ne 0) { break }
                    Start-Sleep -Milliseconds 100
                } while ([DateTime]::UtcNow -lt $uploadStopDeadline)
                if ($uploadAlive.ExitCode -eq 0) { Write-Warning "Upload evidence PID $uploadPid did not exit after SIGTERM." }
            } else {
                Write-Warning "PID $uploadPid no longer identifies this harness's upload test; it was not signalled."
            }
        }
    }
    if ($uploadProcess -and -not $uploadProcess.HasExited) { $uploadProcess.WaitForExit(5000) | Out-Null }
    Remove-Item Env:ED2K_UPLOAD_FILE, Env:ED2K_UPLOAD_PORT -ErrorAction SilentlyContinue
    if (-not $succeeded) { Write-Warning "Harness failed; logs retained at $logsDir" }
}
