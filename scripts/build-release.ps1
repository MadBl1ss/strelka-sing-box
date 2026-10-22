# Builds the release archive: tray from source + package\ templates +
# third-party binaries, checked by sing-box and zipped.
#
#   .\scripts\build-release.ps1 -Bin C:\path\to\binaries
#
# -Bin must hold the unpacked official downloads:
#   sing-box.exe, libcronet.dll, LICENSE     sing-box 1.14 windows-amd64
#                                            (or a previous build's folder)
#   xray.exe, xray-LICENSE.txt               Xray-core 26.3 Xray-windows-64
#   ui\                                      MetaCubeXD gh-pages

param(
    [Parameter(Mandatory)] [string]$Bin,
    [string]$Out = (Join-Path $PSScriptRoot '..\dist')
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$Bin = Resolve-Path $Bin
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = Resolve-Path $Out
$name = 'strelka-sing-box'
$stage = Join-Path $Out $name
$zip = Join-Path $Out "$name-windows-x64.zip"

foreach ($f in 'sing-box.exe', 'libcronet.dll', 'xray.exe', 'xray-LICENSE.txt', 'ui\index.html') {
    if (-not (Test-Path (Join-Path $Bin $f))) { throw "В $Bin нет $f" }
}
# LICENSE в официальном архиве sing-box, sing-box-LICENSE.txt в готовой сборке.
$sbLicense = 'LICENSE', 'sing-box-LICENSE.txt' | ForEach-Object { Join-Path $Bin $_ } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $sbLicense) { throw "В $Bin нет LICENSE от sing-box" }

if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
if (Test-Path $zip) { Remove-Item -Force $zip }
New-Item -ItemType Directory $stage | Out-Null

Write-Host 'Сборка sing-box-tray.exe'
Push-Location (Join-Path $root 'tray')
try {
    go build -ldflags '-H=windowsgui -s -w' -trimpath -o (Join-Path $stage 'sing-box-tray.exe') .
    if ($LASTEXITCODE) { throw 'go build failed' }
} finally { Pop-Location }

Copy-Item -Recurse (Join-Path $root 'package\*') $stage
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $stage 'LICENSE.txt')
foreach ($f in 'sing-box.exe', 'libcronet.dll', 'xray.exe', 'xray-LICENSE.txt') {
    Copy-Item (Join-Path $Bin $f) $stage
}
Copy-Item $sbLicense (Join-Path $stage 'sing-box-LICENSE.txt')
Copy-Item -Recurse (Join-Path $Bin 'ui') (Join-Path $stage 'ui')

# A configured copy must never ship: these hold someone's keys.
$leaks = Get-ChildItem -Recurse $stage -Include 'hwid.txt', 'xray.json', 'cache.db', '*.log', 'config.bak.json', 'config.before-*.json'
if ($leaks) { throw "В сборку попали личные файлы: $($leaks.Name -join ', ')" }
$servers = Get-Content -Raw (Join-Path $stage 'rules\servers-dns.json') | ConvertFrom-Json
if ($servers.rules.Count) { throw 'rules\servers-dns.json должен быть пустым' }
$cfg = Get-Content -Raw (Join-Path $stage 'config.json') | ConvertFrom-Json
if ($cfg.outbounds.Count -ne 2 -or $cfg.experimental.clash_api.secret) {
    throw 'config.json должен быть шаблоном: только proxy и direct, без secret'
}
$sub = Get-Content (Join-Path $stage 'subscription.txt') | Where-Object { $_ -and -not $_.StartsWith('#') }
if ($sub) { throw 'В subscription.txt есть ссылка, нужен пустой шаблон' }

Write-Host 'Проверка config.json через sing-box check'
& (Join-Path $stage 'sing-box.exe') check -c (Join-Path $stage 'config.json') -D $stage
if ($LASTEXITCODE) { throw 'sing-box check failed' }

Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
$size = (Get-Item $zip).Length
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
Write-Host ("Готово: {0}  {1:N1} МБ" -f $zip, ($size / 1MB))
Write-Host "SHA-256: $hash"
