#requires -Version 7.2
[CmdletBinding()]
param([string]$Archive)

$ErrorActionPreference = 'Stop'
$version = '26.11.9'
$archiveHash = '1262522266337B824F07BEB8E1375786B437683B3890105469088F8E17E0A69D'
$root = Split-Path -Parent $PSScriptRoot
$assets = Join-Path $root 'assets'
$runtimePath = Join-Path $assets 'runtime.pack'
$work = Join-Path ([IO.Path]::GetTempPath()) ('orbit-xray-' + [guid]::NewGuid().ToString('N'))
$staged = Join-Path $assets ('runtime-' + [guid]::NewGuid().ToString('N') + '.tmp')
New-Item -ItemType Directory -Path $work | Out-Null

try {
    if ($Archive) {
        $archivePath = (Resolve-Path -LiteralPath $Archive).Path
    } else {
        $archivePath = Join-Path $work 'Xray-windows-64.zip'
        $url = "https://github.com/XTLS/Xray-core/releases/download/v$version/Xray-windows-64.zip"
        Invoke-WebRequest -Uri $url -OutFile $archivePath
    }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $archiveHash) {
        throw 'Xray archive does not match the expected SHA-256.'
    }

    $archiveReader = [IO.Compression.ZipFile]::OpenRead($archivePath)
    $writer = $null
    try {
        $writer = [IO.BinaryWriter]::new([IO.File]::Create($staged))
        foreach ($name in @('xray.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat', 'LICENSE', 'LICENSE-Wintun')) {
            $entry = $archiveReader.GetEntry($name)
            if ($null -eq $entry) { throw "Missing Xray archive entry $name" }
            $content = [IO.MemoryStream]::new()
            $compressed = [IO.MemoryStream]::new()
            try {
                $reader = $entry.Open()
                try { $reader.CopyTo($content) } finally { $reader.Dispose() }
                $bytes = $content.ToArray()
                $encoder = [IO.Compression.ZLibStream]::new(
                    $compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
                try { $encoder.Write($bytes) } finally { $encoder.Dispose() }
                $packed = $compressed.ToArray()
                $writer.Write([uint32]$packed.Length)
                $writer.Write([uint32]$bytes.Length)
                $writer.Write([Security.Cryptography.SHA256]::HashData($bytes))
                $writer.Write($packed)
            } finally {
                $content.Dispose()
                $compressed.Dispose()
            }
        }
    } finally {
        if ($null -ne $writer) { $writer.Dispose() }
        $archiveReader.Dispose()
    }
    [IO.File]::Move($staged, $runtimePath, $true)
    Write-Output "Prepared $runtimePath"
} finally {
    if (Test-Path -LiteralPath $staged) { [IO.File]::Delete($staged) }
    $downloadPath = Join-Path $work 'Xray-windows-64.zip'
    if (Test-Path -LiteralPath $downloadPath) { [IO.File]::Delete($downloadPath) }
    [IO.Directory]::Delete($work)
}
