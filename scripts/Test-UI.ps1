[CmdletBinding()]
param(
    [string]$Executable,
    [string]$Image,
    [ValidateRange(1, 600)]
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$projectPath = Join-Path $root 'src\XeonV3Control.App\XeonV3Control.App.csproj'
$localizationPath = Join-Path $root 'src\XeonV3Control.Core\Localization'
$uiSmokeSwitch = '--ui-smoke'

if (-not $Executable) {
    $projectXml = [xml](Get-Content -LiteralPath $projectPath -Raw)
    $assemblyNameNode = @($projectXml.Project.PropertyGroup.AssemblyName | Where-Object { $_ }) | Select-Object -First 1
    $assemblyName = [string]$assemblyNameNode
    if ([string]::IsNullOrWhiteSpace($assemblyName) -or [IO.Path]::GetFileName($assemblyName) -ne $assemblyName) {
        throw 'Application AssemblyName is missing or invalid.'
    }
    $Executable = Join-Path $root (Join-Path 'publish' ($assemblyName + '.exe'))
}
if (-not $Image) { throw 'Pass -Image with a known UEFI image. This check never loads the driver or reads the board.' }

$Executable = (Resolve-Path -LiteralPath $Executable).Path
$Image = (Resolve-Path -LiteralPath $Image).Path
$cultures = @(Get-ChildItem -LiteralPath $localizationPath -Filter '*.json' -File | ForEach-Object BaseName | Sort-Object -Unique)
if ($cultures.Count -eq 0) { throw 'No localization resources were found.' }

[int]$timeoutMilliseconds = $TimeoutSeconds * 1000
foreach ($culture in $cultures) {
    $output = Join-Path $root ("artifacts\ui-$culture-" + [Guid]::NewGuid().ToString('N'))
    $startInfo = [Diagnostics.ProcessStartInfo]::new($Executable)
    $startInfo.UseShellExecute = $false
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    foreach ($argument in @($uiSmokeSwitch, $output, $culture, $Image)) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) { throw "UI process could not be started: $culture" }
    try {
        if (-not $process.WaitForExit($timeoutMilliseconds)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "UI timeout: $culture"
        }

        $result = Join-Path $output 'result.txt'
        if (-not (Test-Path -LiteralPath $result)) { throw "UI startup failure: $culture, exit $($process.ExitCode)" }
        $content = Get-Content -LiteralPath $result -Raw
        if ($content -notlike 'PASS *') { throw $content }
        Write-Host "$content : $output"
    }
    finally {
        $process.Dispose()
    }
}
