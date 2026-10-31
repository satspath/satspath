# Separate optional experiment. Run within five minutes of the federation smoke.
param([Parameter(Mandatory)][string]$Artifacts, [string]$ClientImage = '')
$ErrorActionPreference = 'Stop'
$nodeExe = (Get-Command node).Source
$suffix = if ($IsWindows) { '.exe' } else { '' }
$clientExe = if (-not $ClientImage) { (Resolve-Path "target/debug/examples/lab_client$suffix").Path } else { '' }
$pin = Join-Path $Artifacts 'trusted-descriptor.json'
$envelope = Join-Path $Artifacts 'public-envelope.json'
$profile = Join-Path $Artifacts 'public-profile.json'
function Verify-Transport($PublicProfile, [bool]$ShouldPass = $true) {
    if ($ClientImage) {
        $relative = [System.IO.Path]::GetRelativePath($Artifacts,$PublicProfile).Replace('\','/')
        & docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$Artifacts,destination=/evidence,readonly" --entrypoint lab_client $ClientImage verify-transport /evidence/trusted-descriptor.json /evidence/public-envelope.json "/evidence/$relative"
    } else {
        & $clientExe verify-transport $pin $envelope $PublicProfile
    }
    if (($LASTEXITCODE -eq 0) -ne $ShouldPass) { throw 'unexpected independent verification result' }
}
Verify-Transport $profile
$outputDir = Join-Path $Artifacts "hyperswarm-$([guid]::NewGuid())"
[void][System.IO.Directory]::CreateDirectory($outputDir)
$candidate = Join-Path $outputDir 'candidate.json'
function Start-Peer([string[]]$PeerArguments, [bool]$Publisher = $false) {
    $info = [System.Diagnostics.ProcessStartInfo]::new($nodeExe)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in $PeerArguments) { $info.ArgumentList.Add($arg) }
    $process = [System.Diagnostics.Process]::Start($info)
    $output = if (-not $Publisher) { $process.StandardOutput.ReadToEndAsync() } else { $null }
    return @{ Process=$process; Out=$output; Err=$process.StandardError.ReadToEndAsync() }
}
$publisher = $null
$resolver = $null
try {
    $publisher = Start-Peer @('sdk/satspath-p2p/examples/publish.mjs','alice@lab.satspath.test',$profile) $true
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline -and -not $publisher.Process.HasExited) {
        $line = $publisher.Process.StandardOutput.ReadLineAsync()
        $remaining = [Math]::Max(1,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds)
        if (-not $line.Wait($remaining)) { break }
        $message = $line.GetAwaiter().GetResult()
        Write-Output $message
        if ($message -eq 'Waiting for peers') { $ready=$true; break }
        if ($null -eq $message) { break }
    }
    if (-not $ready) { throw 'Hyperswarm publisher did not confirm its DHT announcement before deadline' }
    $publisher.Out = $publisher.Process.StandardOutput.ReadToEndAsync()
    $resolver = Start-Peer @('sdk/satspath-p2p/examples/resolve.mjs','alice@lab.satspath.test',$candidate)
    if (-not $resolver.Process.WaitForExit(45000)) { throw 'Hyperswarm experiment exceeded deadline' }
    Write-Output $resolver.Out.GetAwaiter().GetResult()
    if ($resolver.Process.ExitCode) { throw "Hyperswarm unavailable: $($resolver.Err.GetAwaiter().GetResult())" }
    Verify-Transport $candidate
    $tampered = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json
    $tampered.profile.methods[0].lightning_address = 'attacker@example.com'
    $tamperedPath = Join-Path $outputDir 'tampered-candidate.json'
    $tampered | ConvertTo-Json -Depth 100 | Set-Content -Encoding utf8NoBOM $tamperedPath
    Verify-Transport $tamperedPath $false
    Write-Output "PASS: two Hyperswarm peers, public candidate verified against S2S evidence, changed destination rejected. Artifacts: $outputDir"
} finally {
    foreach ($peer in @($publisher,$resolver)) {
        if ($peer -and -not $peer.Process.HasExited) { $peer.Process.Kill(); $peer.Process.WaitForExit() }
        if ($peer) { $peer.Process.Dispose() }
    }
}
