# Benchmarks every server from the subscription: latency + download speed,
# then ranks them and offers to switch config.json to the winner.
# Does not need administrator rights - it uses local SOCKS ports, not the TUN.

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$cfgPath = Join-Path $PSScriptRoot 'config.json'
$exePath = Join-Path $PSScriptRoot 'sing-box.exe'
$tmpPath = Join-Path $PSScriptRoot 'bench.json'
$curl    = Join-Path $env:SystemRoot 'System32\curl.exe'

$PING_URL  = 'http://www.gstatic.com/generate_204'
$SPEED_URL = 'https://speed.cloudflare.com/__down?bytes=8000000'
$PING_TRIES = 3
$PING_LIMIT_MS = 600   # slower than this: shown as ">600 ms" and not tested further
$SPEED_TIMEOUT = 12

function PortUsable([int]$port) {
    try {
        $ex = netsh interface ipv4 show excludedportrange protocol=tcp 2>$null | Select-String '^\s*(\d+)\s+(\d+)'
        foreach ($m in $ex) {
            if ($port -ge [int]$m.Matches[0].Groups[1].Value -and $port -le [int]$m.Matches[0].Groups[2].Value) { return $false }
        }
    } catch {}
    try {
        $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        $l.Start(); $l.Stop(); return $true
    } catch { return $false }
}

# Servers are tagged "<provider>-<name>" (klex-SW, lider-DE2): the provider is
# the name given to its subscription in subscription.txt.
function Provider([string]$tag) {
    if ($tag -match '^([^-]+)-') { return $matches[1] }
    return '-'
}
function Who($r) { return "$($r.Tag) (провайдер $($r.Provider))" }

# Windows PowerShell 5.1 writes "-Encoding UTF8" with a BOM, and sing-box
# refuses a config that starts with one. Write the bytes directly instead,
# so the test works without PowerShell 7.
function Write-Json([string]$path, $obj) {
    $json = $obj | ConvertTo-Json -Depth 40
    [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding $false))
}

if (-not (Test-Path $curl)) { Write-Host 'curl.exe не найден в System32.' -ForegroundColor Red; Read-Host; exit 1 }

try { Clear-Host } catch {}
Write-Host ''
Write-Host '  ТЕСТ СЕРВЕРОВ' -ForegroundColor Cyan
Write-Host ''

$cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
$servers = @($cfg.outbounds | Where-Object { $_.type -in 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'socks' })
if ($servers.Count -eq 0) { Write-Host '  В config.json нет серверов.' -ForegroundColor Red; Read-Host; exit 1 }

# --- give every server its own local port ------------------------------
$ports = @{}
$busy = @([int]($cfg.experimental.clash_api.external_controller -split ':')[-1])
foreach ($inb in $cfg.inbounds) { if ($inb.listen_port) { $busy += [int]$inb.listen_port } }
$cand = 21000
foreach ($s in $servers) {
    while ($busy -contains $cand -or -not (PortUsable $cand)) { $cand++; if ($cand -gt 21500) { break } }
    $ports[$s.tag] = $cand; $busy += $cand; $cand++
}

$inbounds = @()
$rules = @()
foreach ($s in $servers) {
    $inbounds += [pscustomobject][ordered]@{ type='mixed'; tag="in-$($s.tag)"; listen='127.0.0.1'; listen_port=$ports[$s.tag] }
    $rules    += [pscustomobject][ordered]@{ inbound=@("in-$($s.tag)"); outbound=$s.tag }
}

$bench = [pscustomobject][ordered]@{
    log       = [pscustomobject][ordered]@{ level='error'; output='bench.log' }
    dns       = [pscustomobject][ordered]@{ servers=@([pscustomobject][ordered]@{ type='local'; tag='dns-direct' }); final='dns-direct'; strategy='ipv4_only' }
    inbounds  = $inbounds
    outbounds = @($servers) + @([pscustomobject][ordered]@{ type='direct'; tag='direct' })
    route     = [pscustomobject][ordered]@{ rules=$rules; final='direct'; default_domain_resolver='dns-direct' }
}
Write-Json $tmpPath $bench

& $exePath check -c $tmpPath 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host '  Не удалось собрать конфиг для теста:' -ForegroundColor Red
    & $exePath check -c $tmpPath
    Read-Host '  Enter'; exit 1
}

Get-Process 'sing-box' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

Write-Host "  Проверяю $($servers.Count) серверов..." -ForegroundColor Gray
Write-Host ''
# Servers of type socks live in xray.exe (see xray.json). It runs with the VPN;
# if it is down, bring it up just for the test.
$xproc = $null
$xrayExe = Join-Path $PSScriptRoot 'xray.exe'
if (($servers | Where-Object { $_.type -eq 'socks' }) -and (Test-Path $xrayExe) -and
    (Test-Path (Join-Path $PSScriptRoot 'xray.json')) -and -not (Get-Process 'xray' -ErrorAction SilentlyContinue)) {
    $xproc = Start-Process -FilePath $xrayExe -ArgumentList 'run', '-c', 'xray.json' -PassThru -WindowStyle Hidden
}
$proc = Start-Process -FilePath $exePath -ArgumentList 'run', '-c', 'bench.json' -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $PSScriptRoot 'bench-error.log')
Start-Sleep -Seconds 3

if ($proc.HasExited) {
    Write-Host '  sing-box не запустился:' -ForegroundColor Red
    Get-Content (Join-Path $PSScriptRoot 'bench-error.log') -Tail 6 -ErrorAction SilentlyContinue
    Read-Host '  Enter'; exit 1
}

# --- measure ------------------------------------------------------------
# Ping first, every server at once, each try capped at $PING_LIMIT_MS: a slow
# server is not waited out, it just gets ">600 ms". curl exit code 28 is its
# own timeout; any other failure (refused, reset, DNS) means "unreachable".
$limitSec = ($PING_LIMIT_MS / 1000).ToString([Globalization.CultureInfo]::InvariantCulture)
$pings = @{}; $timedOut = @{}
foreach ($s in $servers) { $pings[$s.tag] = @(); $timedOut[$s.tag] = $false }

$results = @()
try {
    for ($i = 0; $i -lt $PING_TRIES; $i++) {
        $running = @()
        foreach ($s in $servers) {
            $psi = New-Object Diagnostics.ProcessStartInfo $curl
            $psi.Arguments = "-s -o NUL --max-time $limitSec -w ""%{http_code} %{time_total}"" -x http://127.0.0.1:$($ports[$s.tag]) $PING_URL"
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.CreateNoWindow = $true
            $running += [pscustomobject]@{ Tag = $s.tag; Proc = [Diagnostics.Process]::Start($psi) }
        }
        foreach ($r in $running) {
            $out = $r.Proc.StandardOutput.ReadToEnd()
            $r.Proc.WaitForExit()
            # Only a real 204 counts: a dead server makes sing-box answer the
            # proxy request with an instant error code, which is not a ping.
            if ($r.Proc.ExitCode -eq 0 -and $out -match '^(\d{3})\s+([\d\.,]+)$' -and $matches[1] -eq '204') {
                $pings[$r.Tag] += [double]($matches[2] -replace ',', '.') * 1000
            } elseif ($r.Proc.ExitCode -eq 28) {
                $timedOut[$r.Tag] = $true
            }
        }
    }

    foreach ($s in $servers) {
        $tag  = $s.tag
        $prov = Provider $tag
        $prx  = "http://127.0.0.1:$($ports[$tag])"
        Write-Host ("   {0,-6} " -f $prov) -NoNewline -ForegroundColor DarkCyan
        Write-Host ("{0,-18} " -f $tag) -NoNewline -ForegroundColor White

        if ($pings[$tag].Count -eq 0) {
            $slow = $timedOut[$tag]
            if ($slow) { Write-Host ('пинг >{0} ms' -f $PING_LIMIT_MS) -ForegroundColor DarkYellow }
            else { Write-Host 'недоступен' -ForegroundColor Red }
            $results += [pscustomobject]@{ Tag=$tag; Provider=$prov; Server=$s.server; Ping=$null; Speed=0; Country='--'; Ok=$false; Slow=$slow }
            continue
        }

        $ping = [math]::Round((($pings[$tag] | Sort-Object)[[int]($pings[$tag].Count / 2)]), 0)
        Write-Host ("пинг {0,5} ms   " -f $ping) -NoNewline -ForegroundColor Gray

        # Where does traffic actually surface? A fast server that exits in Russia
        # is useless for Discord/ChatGPT/Claude, so this column matters.
        $cc = '??'
        try {
            $geo = & $curl -s --max-time 5 -x $prx 'http://ip-api.com/json/?fields=countryCode' 2>$null
            if ($geo -match '"countryCode"\s*:\s*"([A-Z]{2})"') { $cc = $matches[1] }
        } catch {}
        Write-Host ("{0,-3} " -f $cc) -NoNewline -ForegroundColor Cyan

        $sp = & $curl -s -o NUL --max-time $SPEED_TIMEOUT -w '%{speed_download}' -x $prx $SPEED_URL 2>$null
        $bps = 0.0
        if ($sp) { [double]::TryParse(($sp -replace ',', '.'), [ref]$bps) | Out-Null }
        $mbps = [math]::Round($bps * 8 / 1000000, 1)

        if ($mbps -gt 0) { Write-Host ("{0,6} Мбит/с" -f $mbps) -ForegroundColor Green }
        else { Write-Host '  скорость не измерилась' -ForegroundColor DarkYellow }

        $results += [pscustomobject]@{ Tag=$tag; Provider=$prov; Server=$s.server; Ping=$ping; Speed=$mbps; Country=$cc; Ok=$true; Slow=$false }
    }
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    if ($xproc -and -not $xproc.HasExited) { Stop-Process -Id $xproc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $PSScriptRoot 'bench.log') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $PSScriptRoot 'bench-error.log') -Force -ErrorAction SilentlyContinue
}

# --- rank ---------------------------------------------------------------
$live = @($results | Where-Object { $_.Ok -and $_.Speed -gt 0 })
if ($live.Count -eq 0) {
    Write-Host ''
    Write-Host '  Ни один сервер не ответил. Проверь интернет и подписку.' -ForegroundColor Red
    Write-Host ''
    Read-Host '  Enter'; exit 1
}

$maxSpeed = ($live | Measure-Object Speed -Maximum).Maximum
$minPing  = ($live | Measure-Object Ping  -Minimum).Minimum
foreach ($r in $live) {
    # 70% вес скорости, 30% пинга - оба в долях от лучшего результата
    $r | Add-Member -NotePropertyName Score -NotePropertyValue ([math]::Round(
        0.7 * ($r.Speed / $maxSpeed) + 0.3 * ($minPing / [math]::Max($r.Ping, 1)), 3)) -Force
}
$ranked = @($live | Sort-Object Score -Descending)

Write-Host ''
Write-Host '  РЕЗУЛЬТАТ' -ForegroundColor Cyan
Write-Host ''
Write-Host '    #  провайдер  сервер             выход   пинг      скорость        оценка' -ForegroundColor DarkGray
$i = 0
foreach ($r in $ranked) {
    $i++
    $color = if ($i -le 3) { 'Green' } else { 'Gray' }
    $mark  = if ($i -le 3) { '*' } else { ' ' }
    Write-Host ("  {0}{1,2}. {2,-10} {3,-18} {4,-4} {5,5} ms {6,8} Мбит/с {7,8}" -f $mark, $i, $r.Provider, $r.Tag, $r.Country, $r.Ping, $r.Speed, $r.Score) -ForegroundColor $color
}
foreach ($r in ($results | Where-Object { -not $_.Ok -and $_.Slow })) {
    Write-Host ("      -. {0,-10} {1,-18}        >{2} ms" -f $r.Provider, $r.Tag, $PING_LIMIT_MS) -ForegroundColor DarkYellow
}
foreach ($r in ($results | Where-Object { -not $_.Ok -and -not $_.Slow })) {
    Write-Host ("      -. {0,-10} {1,-18}   недоступен" -f $r.Provider, $r.Tag) -ForegroundColor DarkRed
}

$top = $ranked | Select-Object -First 3
Write-Host ''
Write-Host "  ТОП-3 по скорости: $(($top | ForEach-Object { Who $_ }) -join ', ')" -ForegroundColor Green
$fastPing = ($ranked | Sort-Object Ping | Select-Object -First 1)
Write-Host "  Лучший пинг: $(Who $fastPing) ($($fastPing.Ping) ms)" -ForegroundColor DarkGray

# A Russian exit will not unblock Discord/ChatGPT/Claude no matter how fast it is,
# so the recommendation has to skip those.
$foreign = @($ranked | Where-Object { $_.Country -ne 'RU' -and $_.Country -ne '??' })
$best = if ($foreign.Count -gt 0) { $foreign[0] } else { $ranked[0] }
if ($foreign.Count -gt 0 -and $ranked[0].Country -eq 'RU') {
    Write-Host ''
    Write-Host "  ! Быстрее всех $(Who $ranked[0]), но он с выходом в RU - Discord, ChatGPT и Claude" -ForegroundColor Yellow
    Write-Host "    через него не заработают. Лучший пригодный: $(Who $best) ($($best.Country), $($best.Speed) Мбит/с)" -ForegroundColor Yellow
}
$cur  = ($cfg.outbounds | Where-Object { $_.type -eq 'selector' } | Select-Object -First 1).default
Write-Host ''
if ($cur -eq $best.Tag) {
    Write-Host "  Сейчас уже выбран $(Who $best) - он же и лучший." -ForegroundColor Green
} else {
    Write-Host "  Сейчас выбран: $cur. Лучший по тесту: $(Who $best)." -ForegroundColor Yellow
    if ($cur -eq 'auto') {
        Write-Host "  (auto сам выбирает сервер по пингу; после переключения VPN будет всегда идти через $($best.Tag))" -ForegroundColor DarkGray
    }
    $ans = Read-Host '  Переключить config.json на лучший? (y/N)'
    if ($ans -match '^(y|д)') {
        $sel = $cfg.outbounds | Where-Object { $_.type -eq 'selector' } | Select-Object -First 1
        $sel.default = $best.Tag
        # Into a side file first: config.json is replaced only once the core
        # has accepted the result, so a bad write can never stop the VPN.
        $newPath = Join-Path $PSScriptRoot 'config.test-new.json'
        Write-Json $newPath $cfg
        & $exePath check -c $newPath 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Move-Item $newPath $cfgPath -Force
            Write-Host "  Готово: теперь по умолчанию $(Who $best). Перезапусти VPN." -ForegroundColor Green
        } else {
            Remove-Item $newPath -Force -ErrorAction SilentlyContinue
            Write-Host '  Не получилось: config.json не тронут, выбери сервер в меню щита.' -ForegroundColor Red
        }
    }
}

Write-Host ''
Read-Host '  Enter для выхода' | Out-Null
