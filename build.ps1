param([switch]$Test, [switch]$Package)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if ($Test) {
        cargo test --locked
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    }
    cargo build --locked --release
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    $metadataJson = cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'Could not read Cargo metadata' }
    $metadata = $metadataJson | ConvertFrom-Json
    $dist = Join-Path $PSScriptRoot 'dist'
    $program = Join-Path $dist 'ZjuNetAssistant.exe'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    Copy-Item -LiteralPath (Join-Path $metadata.target_directory 'release\zju-net-assistant.exe') -Destination $program
    Copy-Item -LiteralPath LICENSE,THIRD_PARTY_NOTICES.txt -Destination $dist
    Write-Host 'Built dist\ZjuNetAssistant.exe'

    if ($Package) {
        $version = ($metadata.packages | Where-Object { $_.name -eq 'zju-net-assistant' }).version
        $packageName = "ZjuNetAssistant-$version"
        $zipName = "$packageName-Windows-x64.zip"
        $archive = Join-Path $dist $zipName
        $temporary = Join-Path $dist ('.package-' + [Guid]::NewGuid().ToString('N'))
        $stage = Join-Path $temporary $packageName
        New-Item -ItemType Directory -Path $stage | Out-Null
        try {
            Copy-Item -LiteralPath $program,README.md,LICENSE,THIRD_PARTY_NOTICES.txt,dependency-licenses -Destination $stage -Recurse
            Compress-Archive -LiteralPath $stage -DestinationPath $archive -Force -WarningAction SilentlyContinue
            $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $zipName" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
            Write-Host "Packaged dist\$zipName and dist\$zipName.sha256"
        } finally {
            $resolved = (Resolve-Path -LiteralPath $temporary).ProviderPath
            if ((Split-Path -Parent $resolved) -eq $dist -and (Split-Path -Leaf $resolved) -match '^\.package-[a-f0-9]{32}$') {
                Remove-Item -LiteralPath $resolved -Recurse -Force
            }
        }
    }
} finally { Pop-Location }
