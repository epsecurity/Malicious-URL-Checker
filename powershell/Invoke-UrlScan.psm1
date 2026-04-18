<#
.SYNOPSIS
Trigger the malicious-url-checker GitHub Actions workflow, wait for completion,
download the artifact, and render the verdict in the terminal.

.DESCRIPTION
Requires environment variables (or PowerShell variables) set before use:
  $env:GH_DISPATCH_TOKEN   Fine-grained PAT with contents:write + actions:read on the repo
  $env:GH_REPO_OWNER       Your GitHub username / org
  $env:GH_REPO_NAME        Repo name (e.g. malicious-url-checker)

.EXAMPLE
Invoke-UrlScan -Url "https://suspicious.example.com"

.EXAMPLE
Invoke-UrlScan -Url "https://suspicious.example.com" -OpenReport

.EXAMPLE
Invoke-UrlScan -Url "https://suspicious.example.com" -Json | ConvertFrom-Json
#>

function Invoke-UrlScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Url,

        [Parameter()]
        [int]$TimeoutSeconds = 900,

        [Parameter()]
        [int]$PollIntervalSeconds = 10,

        [Parameter()]
        [switch]$OpenReport,

        [Parameter()]
        [switch]$Json,

        [Parameter()]
        [string]$Token = $env:GH_DISPATCH_TOKEN,

        [Parameter()]
        [string]$Owner = $env:GH_REPO_OWNER,

        [Parameter()]
        [string]$Repo = $env:GH_REPO_NAME
    )

    if ([string]::IsNullOrWhiteSpace($Token)) { throw "GH_DISPATCH_TOKEN not set" }
    if ([string]::IsNullOrWhiteSpace($Owner)) { throw "GH_REPO_OWNER not set" }
    if ([string]::IsNullOrWhiteSpace($Repo))  { throw "GH_REPO_NAME not set" }

    $runToken = [guid]::NewGuid().ToString()
    $headers = @{
        Authorization = "Bearer $Token"
        Accept        = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }

    # 1. Fire repository_dispatch
    $dispatchBody = @{
        event_type = "analyze-url"
        client_payload = @{
            url       = $Url
            run_token = $runToken
        }
    } | ConvertTo-Json -Depth 4

    if (-not $Json) { Write-Host "[+] Dispatching workflow for $Url" -ForegroundColor Cyan }

    Invoke-RestMethod `
        -Uri "https://api.github.com/repos/$Owner/$Repo/dispatches" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $dispatchBody | Out-Null

    # 2. Find the run we just triggered (poll runs endpoint for one matching our run_token via display_title/name)
    #    Since repository_dispatch runs don't carry custom names, we match by event + created_at proximity.
    if (-not $Json) { Write-Host "[+] Waiting for workflow run to start..." -ForegroundColor Cyan }
    $runId = $null
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline -and -not $runId) {
        Start-Sleep -Seconds 3
        $runs = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$Owner/$Repo/actions/workflows/analyze-url.yml/runs?event=repository_dispatch&per_page=10" `
            -Headers $headers
        foreach ($run in $runs.workflow_runs) {
            # Match: event=repository_dispatch, status in queued/in_progress, created within last 2 min
            $age = (Get-Date) - [datetime]::Parse($run.created_at)
            if ($age.TotalSeconds -lt 120 -and $run.status -in @("queued", "in_progress", "waiting")) {
                $runId = $run.id
                break
            }
        }
    }

    if (-not $runId) {
        throw "Could not locate triggered workflow run within 60s. Check https://github.com/$Owner/$Repo/actions"
    }

    if (-not $Json) { Write-Host "[+] Run: https://github.com/$Owner/$Repo/actions/runs/$runId" -ForegroundColor Cyan }

    # 3. Poll for completion
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $run = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $run = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$Owner/$Repo/actions/runs/$runId" `
            -Headers $headers
        if ($run.status -eq "completed") { break }
        if (-not $Json) { Write-Host "    status: $($run.status)" -ForegroundColor DarkGray }
    }

    if ($run.status -ne "completed") {
        throw "Workflow did not complete within $TimeoutSeconds seconds (last status: $($run.status))"
    }

    if ($run.conclusion -ne "success") {
        Write-Warning "Workflow conclusion: $($run.conclusion). Artifact may still be available."
    }

    # 4. Download artifact
    $artifacts = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/$Owner/$Repo/actions/runs/$runId/artifacts" `
        -Headers $headers

    $artifact = $artifacts.artifacts | Where-Object { $_.name -like "analyze-url-*" } | Select-Object -First 1
    if (-not $artifact) { throw "No artifact found on run $runId" }

    $tempZip = Join-Path ([System.IO.Path]::GetTempPath()) "urlscan-$runId.zip"
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "urlscan-$runId"

    Invoke-WebRequest `
        -Uri $artifact.archive_download_url `
        -Headers $headers `
        -OutFile $tempZip

    if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
    Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force

    $summaryPath = Join-Path $tempDir "summary.json"
    if (-not (Test-Path $summaryPath)) { throw "summary.json missing from artifact" }

    $summary = Get-Content $summaryPath -Raw | ConvertFrom-Json

    # 5. Output
    if ($Json) {
        $summary | ConvertTo-Json -Depth 10
        return
    }

    Write-Host ""
    Write-Host "URL Analysis: $($summary.url_defanged)" -ForegroundColor White
    Write-Host ""

    $verdictColor = switch ($summary.verdict) {
        "malicious"         { "Red" }
        "suspicious"        { "Yellow" }
        "clean"             { "Green" }
        default             { "DarkGray" }
    }
    Write-Host "  Verdict:       " -NoNewline
    Write-Host "$($summary.verdict.ToUpper())" -ForegroundColor $verdictColor -NoNewline
    Write-Host "     Confidence: $([math]::Round($summary.confidence, 2))"

    Write-Host "  Action:        $($summary.recommended_action)"
    Write-Host "  Summary:       $($summary.summary)"
    Write-Host ""
    Write-Host "  Key Indicators:"
    if ($summary.key_indicators.Count -gt 0) {
        foreach ($ind in $summary.key_indicators) {
            Write-Host "    - $ind"
        }
    } else {
        Write-Host "    (none)"
    }

    Write-Host ""
    if ($null -ne $summary.domain_age_days) {
        Write-Host "  Domain age:    $($summary.domain_age_days) days ($($summary.registrar))"
    }
    if ($summary.ip) {
        $abuse = if ($null -ne $summary.abuse_confidence_score) { "$($summary.abuse_confidence_score)/100" } else { "n/a" }
        Write-Host "  Hosting IP:    $($summary.ip)   AbuseIPDB: $abuse"
    }
    if ($summary.urlscan_result_url) {
        Write-Host "  URLScan:       $($summary.urlscan_result_url)"
    }
    Write-Host "  GHA run:       https://github.com/$Owner/$Repo/actions/runs/$runId"
    Write-Host "  Artifact dir:  $tempDir"
    Write-Host ""
    Write-Host "  Reasoning:     $($summary.reasoning_short)" -ForegroundColor Gray
    Write-Host ""

    if ($OpenReport) {
        $reportPath = Join-Path $tempDir "report.html"
        if (Test-Path $reportPath) { Start-Process $reportPath }
    }
}

Export-ModuleMember -Function Invoke-UrlScan
