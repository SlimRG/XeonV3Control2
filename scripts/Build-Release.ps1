[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$configuration = 'Release'
$platform = 'x64'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$appProject = Join-Path $root 'src\XeonV3Control.App\XeonV3Control.App.csproj'
$testProject = Join-Path $root 'tests\XeonV3Control.Tests\XeonV3Control.Tests.csproj'
$probeProject = Join-Path $root 'tools\HardwareProbe\HardwareProbe.csproj'
$driverRoot = Join-Path $root 'third_party\ThrottleStop'
$integrityPath = Join-Path $driverRoot 'integrity.json'
$publishDirectory = Join-Path $root 'publish'
$stage = $null
$publishCandidate = $null
$publishBackup = $null

$integrity = Get-Content -LiteralPath $integrityPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($integrity.FileName) -or
    [IO.Path]::GetFileName($integrity.FileName) -ne $integrity.FileName -or
    $integrity.Sha256 -notmatch '^[0-9A-Fa-f]{64}$' -or
    $integrity.SignerCertificateSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    throw 'ThrottleStop integrity manifest is invalid.'
}
$driverPath = Join-Path $driverRoot $integrity.FileName

[xml]$projectXml = Get-Content -LiteralPath $appProject -Raw -Encoding UTF8
$assemblyNameNode = @($projectXml.Project.PropertyGroup.AssemblyName | Where-Object { $_ }) | Select-Object -First 1
$assemblyName = [string]$assemblyNameNode
if ([string]::IsNullOrWhiteSpace($assemblyName) -or [IO.Path]::GetFileName($assemblyName) -ne $assemblyName) {
    throw 'Application AssemblyName is missing or invalid.'
}

$compressionNode = @($projectXml.Project.PropertyGroup.EnableCompressionInSingleFile | Where-Object { $_ }) | Select-Object -First 1
if ([string]$compressionNode -ne 'true') {
    throw 'Single-file compression must remain enabled for release publishing.'
}

$readyToRunNode = @($projectXml.Project.PropertyGroup.PublishReadyToRun | Where-Object { $_ }) | Select-Object -First 1
if ([string]$readyToRunNode -ne 'false') {
    throw 'ReadyToRun must remain disabled for the compact portable release.'
}

$maximumExecutableMiBNode = @($projectXml.Project.PropertyGroup.ReleaseMaximumExecutableMiB | Where-Object { $_ }) | Select-Object -First 1
$maximumExecutableMiB = 0
if (-not [int]::TryParse([string]$maximumExecutableMiBNode, [ref]$maximumExecutableMiB) -or $maximumExecutableMiB -le 0) {
    throw 'ReleaseMaximumExecutableMiB is missing or invalid.'
}
$maximumExecutableBytes = [int64]$maximumExecutableMiB * 1MB
$executableName = $assemblyName + '.exe'
$releaseId = [Guid]::NewGuid().ToString('N')
$stage = Join-Path ([IO.Path]::GetTempPath()) ($assemblyName + '-release-' + $releaseId)
$publishCandidate = Join-Path $root ('publish.candidate-' + $releaseId)
$publishBackup = Join-Path $root ('publish.backup-' + $releaseId)

Push-Location $root
try {
    $actualDriverHash = (Get-FileHash -LiteralPath $driverPath -Algorithm SHA256).Hash
    if ($actualDriverHash -ne $integrity.Sha256.ToUpperInvariant()) {
        throw 'ThrottleStop driver SHA-256 mismatch.'
    }

    $driverSignature = Get-AuthenticodeSignature -LiteralPath $driverPath
    if ($driverSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $driverSignature.SignerCertificate) {
        throw "ThrottleStop driver Authenticode signature is not valid: $($driverSignature.Status)."
    }

    $signerHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($driverSignature.SignerCertificate.RawData))
    if ($signerHash -ne $integrity.SignerCertificateSha256.ToUpperInvariant()) {
        throw 'ThrottleStop driver signer certificate mismatch.'
    }

    dotnet test $testProject -c $configuration
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }

    # HardwareProbe shares the low-level driver transport; compile it so shared hardware changes cannot silently break it.
    dotnet build $probeProject -c $configuration
    if ($LASTEXITCODE -ne 0) { throw 'HardwareProbe build failed.' }

    dotnet publish $appProject -c $configuration -p:Platform=$platform -o $stage
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

    $entries = @(Get-ChildItem -LiteralPath $stage -Force)
    if ($entries.Count -ne 1 -or $entries[0].PSIsContainer -or $entries[0].Name -ne $executableName) {
        throw "Single EXE publish invariant failed. Found: $($entries.Name -join ', ')"
    }

    $stageExecutableBytes = [int64]$entries[0].Length
    $stageExecutableMiB = $stageExecutableBytes / 1MB
    Write-Host ("Release size: {0:N2} MiB ({1:N0} bytes); limit: {2} MiB" -f
        $stageExecutableMiB, $stageExecutableBytes, $maximumExecutableMiB)
    if ($stageExecutableBytes -gt $maximumExecutableBytes) {
        throw ("Release executable exceeds configured size limit: {0:N2} MiB > {1} MiB." -f
            $stageExecutableMiB, $maximumExecutableMiB)
    }

    New-Item -ItemType Directory -Path $publishCandidate | Out-Null
    $candidateExecutable = Join-Path $publishCandidate $executableName
    Copy-Item -LiteralPath $entries[0].FullName -Destination $candidateExecutable
    $candidateEntries = @(Get-ChildItem -LiteralPath $publishCandidate -Force)
    if ($candidateEntries.Count -ne 1 -or $candidateEntries[0].PSIsContainer -or
        $candidateEntries[0].Name -ne $executableName) {
        throw 'Candidate publish directory invariant failed.'
    }

    $stageHash = (Get-FileHash -LiteralPath $entries[0].FullName -Algorithm SHA256).Hash
    $candidateHash = (Get-FileHash -LiteralPath $candidateExecutable -Algorithm SHA256).Hash
    if ($candidateHash -ne $stageHash) { throw 'Candidate publish copy failed integrity verification.' }

    if (Test-Path -LiteralPath $publishDirectory -PathType Leaf) {
        throw 'Final publish path exists as a file.'
    }

    $hadPreviousRelease = Test-Path -LiteralPath $publishDirectory -PathType Container
    if ($hadPreviousRelease) {
        Move-Item -LiteralPath $publishDirectory -Destination $publishBackup
    }

    try {
        Move-Item -LiteralPath $publishCandidate -Destination $publishDirectory
        $publishCandidate = $null

        $publishedExecutable = Join-Path $publishDirectory $executableName
        $publishedEntries = @(Get-ChildItem -LiteralPath $publishDirectory -Force)
        if ($publishedEntries.Count -ne 1 -or $publishedEntries[0].PSIsContainer -or
            $publishedEntries[0].Name -ne $executableName) {
            throw 'Final publish directory invariant failed.'
        }

        $publishedHash = (Get-FileHash -LiteralPath $publishedExecutable -Algorithm SHA256).Hash
        if ($publishedHash -ne $candidateHash) { throw 'Final publish integrity verification failed.' }
    }
    catch {
        $publishFailure = $_
        try {
            if (Test-Path -LiteralPath $publishDirectory -PathType Container) {
                Remove-Item -LiteralPath $publishDirectory -Recurse -Force -ErrorAction Stop
            }
            if ($hadPreviousRelease -and (Test-Path -LiteralPath $publishBackup -PathType Container)) {
                Move-Item -LiteralPath $publishBackup -Destination $publishDirectory -ErrorAction Stop
                $publishBackup = $null
            }
        }
        catch {
            Write-Warning "Release installation failed and automatic rollback also failed: $_"
        }
        throw $publishFailure
    }

    if ($hadPreviousRelease -and (Test-Path -LiteralPath $publishBackup -PathType Container)) {
        Remove-Item -LiteralPath $publishBackup -Recurse -Force
        $publishBackup = $null
    }

    Write-Host "Release: $publishedExecutable"
    Write-Host ("Release size: {0:N2} MiB ({1:N0} bytes)" -f
        ((Get-Item -LiteralPath $publishedExecutable).Length / 1MB),
        (Get-Item -LiteralPath $publishedExecutable).Length)
    Write-Host 'Single-file compression: enabled; ReadyToRun: disabled; trimming: disabled.'
    Get-FileHash -LiteralPath $publishedExecutable -Algorithm SHA256
}
finally {
    foreach ($temporaryPath in @($stage, $publishCandidate)) {
        if ([string]::IsNullOrWhiteSpace($temporaryPath) -or -not (Test-Path -LiteralPath $temporaryPath)) { continue }
        try {
            Remove-Item -LiteralPath $temporaryPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to remove temporary release path '$temporaryPath': $_"
        }
    }

    # A backup is deliberately retained if rollback itself could not complete; destroying it would lose the last known release.
    if (-not [string]::IsNullOrWhiteSpace($publishBackup) -and
        (Test-Path -LiteralPath $publishBackup -PathType Container)) {
        Write-Warning "Previous release backup was retained at '$publishBackup'."
    }
    Pop-Location
}
