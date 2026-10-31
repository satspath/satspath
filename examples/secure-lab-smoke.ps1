# PowerShell 7, Windows or Ubuntu. Run from the repository root.
param([switch]$SkipBuild, [switch]$Federation)
$ErrorActionPreference = 'Stop'
if (-not $SkipBuild) {
    cargo build -p satspathd --bin satspathd
    if ($LASTEXITCODE) { throw 'daemon build failed' }
    cargo build -p satspath-core --example lab_client
    if ($LASTEXITCODE) { throw 'client build failed' }
}
$suffix = if ($IsWindows) { '.exe' } else { '' }
$daemonExe = (Resolve-Path "target/debug/satspathd$suffix").Path
$clientExe = (Resolve-Path "target/debug/examples/lab_client$suffix").Path
$root = Join-Path ([System.IO.Path]::GetTempPath()) "satspath-secure-lab-$([guid]::NewGuid())"
[void][System.IO.Directory]::CreateDirectory($root)
$token = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$children = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
function Start-LabDaemon($network, $authorityDir, $requestedPort = 0, $replicaPin = '', $replicaOrigins = @()) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $requestedPort)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    $origin = "http://127.0.0.1:$port"
    $info = [System.Diagnostics.ProcessStartInfo]::new($daemonExe)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in @('--no-open', '--network', $network, '--home', $authorityDir, '--bind', "127.0.0.1:$port")) { $info.ArgumentList.Add($arg) }
    if ($replicaPin) {
        foreach ($arg in @('--replica-descriptor', $replicaPin, '--replica-alias', 'alice@lab.satspath.test', '--replica-sync-seconds', '1')) { $info.ArgumentList.Add($arg) }
    }
    $info.Environment['SATSPATHD_AUTH_TOKEN'] = $token
    $info.Environment['SATSPATH_ENABLE_LAB_REGISTRATION'] = '1'
    $info.Environment['SATSPATH_AUTHORITY_URL'] = $origin
    $info.Environment.Remove('SATSPATH_PEPPER') | Out-Null
    $info.Environment.Remove('SATSPATH_REPLICA_URLS') | Out-Null
    if ($replicaOrigins.Count) { $info.Environment['SATSPATH_REPLICA_URLS'] = ConvertTo-Json -InputObject @($replicaOrigins) -Compress }
    if ($replicaPin) { $info.Environment.Remove('SATSPATHD_AUTH_TOKEN') | Out-Null }
    $child = [System.Diagnostics.Process]::Start($info)
    $children.Add($child)
    $outTask = $child.StandardOutput.ReadToEndAsync()
    $errTask = $child.StandardError.ReadToEndAsync()
    for ($i = 0; $i -lt 100; $i++) {
        if ($child.HasExited) { throw "daemon failed: $($errTask.GetAwaiter().GetResult())" }
        try {
            Invoke-RestMethod "$origin/health" -TimeoutSec 1 | Out-Null
            return @{ Origin = $origin; Process = $child; Out = $outTask; Err = $errTask }
        } catch { Start-Sleep -Milliseconds 100 }
    }
    throw 'startup timeout'
}
function Run-Client([string[]]$ClientArgs, [bool]$ShouldPass = $true) {
    $info = [System.Diagnostics.ProcessStartInfo]::new($clientExe)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in $ClientArgs) { $info.ArgumentList.Add($arg) }
    # Only the operator-assisted registration process receives admission rights.
    $info.Environment.Remove('SATSPATHD_AUTH_TOKEN') | Out-Null
    $info.Environment.Remove('SATSPATH_PEPPER') | Out-Null
    if ($ClientArgs[0] -in @('register','update')) { $info.Environment['SATSPATHD_AUTH_TOKEN'] = $token }
    $process = [System.Diagnostics.Process]::Start($info)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(20000)) { $process.Kill(); throw 'client timeout' }
    if (($process.ExitCode -eq 0) -ne $ShouldPass) { throw "unexpected client result: $($stderr.GetAwaiter().GetResult())" }
    if ($ShouldPass) { Write-Output $stdout.GetAwaiter().GetResult().Trim() }
}
function Assert-Rejected($url, $body, $bearer) {
    $headers = @{}
    if ($bearer) { $headers.Authorization = "Bearer $bearer" }
    $response = Invoke-WebRequest $url -Method Post -Headers $headers -ContentType 'application/json' -Body $body -SkipHttpErrorCheck
    if ([int]$response.StatusCode -lt 400) { throw "unsafe acceptance at $url" }
}
function Wait-Replica($origin, $size) {
    for ($i = 0; $i -lt 100; $i++) {
        try {
            $view = Invoke-RestMethod "$origin/v2/resolve?identifier=alice%40lab.satspath.test" -TimeoutSec 2
            if ($view.checkpoint.log_size -eq $size) { return }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    throw "replica failed to reach checkpoint $size"
}
try {
    if ($Federation) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start(); $replicaPort = $listener.LocalEndpoint.Port; $listener.Stop()
        $replicaOrigin = "http://127.0.0.1:$replicaPort"
        $authorityHome = Join-Path $root 'authority'
        $replicaHome = Join-Path $root 'replica'
        $clientHome = Join-Path $root 'client-c'
        $pin = Join-Path $root 'trusted-descriptor.json'
        $authority = Start-LabDaemon 'regtest' $authorityHome 0 '' @($replicaOrigin)
        Run-Client @('bootstrap', $authorityHome, $authority.Origin, $pin)
        Run-Client @('register', $pin, (Join-Path $root 'alice'), 'alice@lab.satspath.test', 'alice@example.com')
        $replica = Start-LabDaemon 'regtest' $replicaHome $replicaPort $pin
        Wait-Replica $replicaOrigin 1
        Run-Client @('resolve', $pin, $clientHome, 'alice@lab.satspath.test')
        Run-Client @('update', $pin, (Join-Path $root 'alice'), 'alice@lab.satspath.test', 'new-destination@example.com')
        Wait-Replica $replicaOrigin 2
        $view = Invoke-RestMethod "$($authority.Origin)/v2/resolve?identifier=alice%40lab.satspath.test"
        $view | ConvertTo-Json -Depth 100 | Set-Content -Encoding utf8NoBOM (Join-Path $root 'public-envelope.json')
        $view.signed_profile | ConvertTo-Json -Depth 100 | Set-Content -Encoding utf8NoBOM (Join-Path $root 'public-profile.json')
        Assert-Rejected "$($authority.Origin)/v1/profile/verify" '{"alias":"support@blink.sv","token":"support@blink.sv"}' $token
        Assert-Rejected "$($replica.Origin)/v1/lab/registrations/reserve" '{"alias":"mallory@lab.satspath.test","identity_pubkey":"invalid"}' $token
        $authority.Process.Kill(); $authority.Process.WaitForExit()
        $resolution = Run-Client @('resolve', $pin, $clientHome, 'alice@lab.satspath.test')
        Write-Output $resolution
        $result = $resolution | ConvertFrom-Json
        if ($result.served_by -ne $replicaOrigin -or $result.tree_size -ne 2 -or $result.profile_sequence -ne 1) { throw 'failover did not verify updated profile from B' }
        $replica.Process.Kill(); $replica.Process.WaitForExit()
        $replica = Start-LabDaemon 'regtest' $replicaHome $replicaPort $pin
        Wait-Replica $replicaOrigin 2
        Run-Client @('resolve', $pin, $clientHome, 'alice@lab.satspath.test')
        foreach ($relative in @('wallet.json','admin.macaroon','identity','transparency/operator.key')) {
            if (Test-Path (Join-Path $replicaHome $relative)) { throw "replica created signing/admin material: $relative" }
        }
        $replica.Process.Kill(); $replica.Process.WaitForExit()
        Run-Client @('resolve', $pin, $clientHome, 'alice@lab.satspath.test') $false
        Write-Output "PASS: A registration/update -> B verified sync -> A offline -> C verified B with continuity -> B restart without keys -> all endpoints down rejected. Artifacts: $root"
        return
    }
    $authorityHome = Join-Path $root 'authority'
    $authority = Start-LabDaemon 'regtest' $authorityHome
    $pin = Join-Path $root 'trusted-descriptor.json'
    Run-Client @('bootstrap', $authorityHome, $authority.Origin, $pin)
    Run-Client @('register', $pin, (Join-Path $root 'alice'), 'alice@lab.satspath.test', 'alice@example.com')
    # Bob is a separate process with no token, owner key, authority DB or SSH.
    Run-Client @('resolve', $pin, (Join-Path $root 'bob'), 'alice@lab.satspath.test')
    Run-Client @('resolve', $pin, (Join-Path $root 'bob'), 'alice@lab.satspath.test')
    Run-Client @('register', $pin, (Join-Path $root 'charlie'), 'charlie@lab.satspath.test', 'charlie@example.com')
    Run-Client @('resolve', $pin, (Join-Path $root 'bob'), 'alice@lab.satspath.test')
    $originalPort = ([uri]$authority.Origin).Port
    $authority.Process.Kill()
    $authority.Process.WaitForExit()
    $authority = Start-LabDaemon 'regtest' $authorityHome $originalPort
    Run-Client @('resolve', $pin, (Join-Path $root 'bob'), 'alice@lab.satspath.test')
    Run-Client @('register', $pin, (Join-Path $root 'attacker'), 'alice@lab.satspath.test', 'attacker@example.com') $false
    $key = ('02' + ('11' * 32))
    $body = @{ alias = 'support@blink.sv'; identity_pubkey = $key } | ConvertTo-Json -Compress
    Assert-Rejected "$($authority.Origin)/v1/lab/registrations/reserve" $body $token
    Assert-Rejected "$($authority.Origin)/v1/lab/registrations/reserve" $body ''
    Assert-Rejected "$($authority.Origin)/v1/profile/verify" '{"alias":"support@blink.sv","token":"support@blink.sv"}' $token
    $mainnet = Start-LabDaemon 'mainnet' (Join-Path $root 'mainnet')
    $body = @{ alias = 'alice@lab.satspath.test'; identity_pubkey = $key } | ConvertTo-Json -Compress
    Assert-Rejected "$($mainnet.Origin)/v1/lab/registrations/reserve" $body $token
    $authority.Process.Kill()
    $authority.Process.WaitForExit()
    Run-Client @('resolve', $pin, (Join-Path $root 'bob'), 'alice@lab.satspath.test') $false
    Write-Output "PASS: independent lab resolution, duplicate/foreign/unauthorized/mainnet rejection and network failure. Artifacts: $root"
} finally {
    foreach ($child in $children) {
        if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
        $child.Dispose()
    }
}
