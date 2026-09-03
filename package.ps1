[CmdletBinding()]
param(
    [switch]$Zip,
    [string]$Name,
    [switch]$IncludeSubmodules
)

# Compress the project into an ultra-level 7z/zip archive,
# excluding everything .gitignore'd and excluding git submodules by default.
# Archive name dynamically defaults to the current project directory name.
# Requires 7z in PATH. Uses all CPU threads and caps memory usage at 80%.

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($root)) {
    $root = (Get-Location).Path
}
Set-Location -LiteralPath $root

$projectName = if (-not [string]::IsNullOrWhiteSpace($Name)) {
    $Name
} else {
    Split-Path -Leaf -Path $root
}

if (-not (Get-Command "7z" -ErrorAction SilentlyContinue)) {
    throw "7z was not found in PATH. Please install 7-Zip or add it to PATH."
}

$format = if ($Zip) { "zip" } else { "7z" }
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$archive = Join-Path $root "$projectName-$stamp.$format"
$listFile = Join-Path $root ".7z-filelist.tmp"

# Detect all git submodule paths (mode 160000 entries in git index)
$submodulePaths = @(git ls-files --stage | Where-Object { $_ -match '^160000' } | ForEach-Object { ($_ -split "`t", 2)[1] })
$submoduleSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($sm in $submodulePaths) {
    if (-not [string]::IsNullOrWhiteSpace($sm)) {
        [void]$submoduleSet.Add($sm.TrimEnd('/').Replace('\', '/'))
    }
}

# git respects .gitignore: tracked files plus untracked non-ignored files
$rawFiles = @(git ls-files --cached --others --exclude-standard)
if (-not $rawFiles -or $rawFiles.Count -eq 0) {
    throw "No files found to archive (is this a git repo with commits?)"
}

# Filter out submodules, directory entries, and archive artifacts
$files = @($rawFiles | Where-Object {
    $p = $_.TrimEnd('/').Replace('\', '/')

    if (-not $IncludeSubmodules) {
        if ($submoduleSet.Contains($p)) { return $false }
        foreach ($sm in $submoduleSet) {
            if ($p.StartsWith("$sm/", [System.StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
        }
    }

    # Exclude archives and temporary list file
    if ($p -match '\.(7z|zip|tmp)$') { return $false }

    # 7-Zip recursively archives any directory path in a listfile; ensure only files are listed
    $full = Join-Path $root $p
    if ((Test-Path -LiteralPath $full) -and (Test-Path -LiteralPath $full -PathType Container)) {
        return $false
    }

    return $true
})

if ($files.Count -eq 0) {
    throw "No eligible files left to archive after filtering."
}

Write-Host "Archiving $($files.Count) files into $format archive..."

try {
    # UTF-8 without BOM listfile; 7z reads this with -sccUTF-8
    [System.IO.File]::WriteAllLines($listFile, $files, [System.Text.UTF8Encoding]::new($false))

    if (Test-Path -LiteralPath $archive) {
        Remove-Item -LiteralPath $archive -Force
    }

    & 7z a "-t$format" `
        -mx=9 `
        -mmt=on `
        '-mmemuse=80%' `
        -sccUTF-8 `
        -aoa `
        $archive "@$listFile"

    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "7z exited with code $code"
    }

    $sizeMb = [math]::Round((Get-Item -LiteralPath $archive).Length / 1MB, 2)
    Write-Host ""
    Write-Host "Created $archive ($sizeMb MiB)"
}
finally {
    Remove-Item -LiteralPath $listFile -Force -ErrorAction SilentlyContinue
}
