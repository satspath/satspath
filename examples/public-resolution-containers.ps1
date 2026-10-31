# PowerShell 7. Separate containers/filesystems, shared loopback network namespace
# for the explicitly permitted HTTP laboratory policy. No host ports published.
param([switch]$KeepContainers)
$ErrorActionPreference = 'Stop'
$project = "satspath-lab-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$env:SATSPATH_LAB_IMAGE = "${project}:local"
$env:SATSPATHD_AUTH_TOKEN = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$compose = @('compose','-p',$project,'-f','docker/public-resolution.compose.yml')
$artifactRoot = Join-Path ([System.IO.Path]::GetTempPath()) "satspath-container-evidence-$project"
[void][System.IO.Directory]::CreateDirectory($artifactRoot)
function Invoke-LabCompose([string[]]$DockerArgs, [bool]$ShouldPass = $true) {
    $output = & docker @compose @DockerArgs 2>&1
    if (($LASTEXITCODE -eq 0) -ne $ShouldPass) { throw ($output -join "`n") }
    return ($output -join "`n")
}
try {
    Write-Output "Building isolated laboratory project $project"
    # Stream build output so slow downloads/compilation remain observable.
    & docker @compose build authority
    if ($LASTEXITCODE) { throw 'lab container build failed' }
    Write-Output (Invoke-LabCompose @('up','-d','--wait','network','authority'))
    # Export in A itself; never mount A's private state into B or C. SQLite WAL
    # may need shared-memory metadata even for a read-only database connection.
    Write-Output (Invoke-LabCompose @('exec','-T','authority','lab_client','bootstrap','/state/authority','http://127.0.0.1:9737','/state/public/descriptor.json'))
    Write-Output (Invoke-LabCompose @('run','--rm','--no-deps','alice'))
    Write-Output (Invoke-LabCompose @('up','-d','--wait','replica'))
    Write-Output (Invoke-LabCompose @('run','--rm','--no-deps','client'))
    Write-Output (Invoke-LabCompose @('run','--rm','--no-deps','alice','lab_client','update','/state/public/descriptor.json','/state/alice','alice@lab.satspath.test','new-destination@example.com'))
    $synced = $false
    for ($i=0; $i -lt 30; $i++) {
        $cached = Invoke-LabCompose @('exec','-T','replica','curl','--fail','--silent','http://127.0.0.1:9738/v2/resolve?identifier=alice%40lab.satspath.test')
        if (($cached | ConvertFrom-Json).checkpoint.log_size -eq 2) { $synced=$true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $synced) { throw 'replica did not verify the owner-signed update' }
    # Export public evidence only, before stopping A. No DB, token or key exports.
    $descriptor = Invoke-LabCompose @('exec','-T','authority','cat','/state/public/descriptor.json')
    $envelope = Invoke-LabCompose @('exec','-T','authority','curl','--fail','--silent','http://127.0.0.1:9737/v2/resolve?identifier=alice%40lab.satspath.test')
    $descriptor | Set-Content -Encoding utf8NoBOM (Join-Path $artifactRoot 'trusted-descriptor.json')
    $envelope | Set-Content -Encoding utf8NoBOM (Join-Path $artifactRoot 'public-envelope.json')
    ($envelope | ConvertFrom-Json).signed_profile | ConvertTo-Json -Depth 100 | Set-Content -Encoding utf8NoBOM (Join-Path $artifactRoot 'public-profile.json')
    Write-Output (Invoke-LabCompose @('stop','authority'))
    $resolved = Invoke-LabCompose @('run','--rm','--no-deps','client')
    Write-Output $resolved
    # Docker status/progress may prefix stdout; parse the final JSON line only.
    $line = ($resolved -split "`n" | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1)
    $result = $line | ConvertFrom-Json
    if ($result.served_by -ne 'http://127.0.0.1:9738' -or $result.tree_size -ne 2 -or $result.profile_sequence -ne 1) { throw 'C did not independently verify the updated profile through replica B' }
    Write-Output (Invoke-LabCompose @('restart','replica'))
    # Resolve after B's HTTP listener has reopened, still without A.
    $success = $false
    for ($i=0; $i -lt 30; $i++) {
        $attempt = & docker @compose run --rm --no-deps client 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Output ($attempt -join "`n"); $success=$true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $success) { throw 'replica failed to serve after restart with authority offline' }
    Write-Output (Invoke-LabCompose @('stop','replica'))
    Write-Output (Invoke-LabCompose @('run','--rm','--no-deps','client') $false)
    Write-Output "PASS: independent A/B/C container filesystems, signed update, verified B failover, restart and total outage rejection. Project: $project; public evidence: $artifactRoot; client image: $env:SATSPATH_LAB_IMAGE"
} finally {
    if (-not $KeepContainers) {
        # Retain named volumes for audit. Remove only this generated project's containers.
        & docker @compose down --remove-orphans | Out-Null
    }
}
