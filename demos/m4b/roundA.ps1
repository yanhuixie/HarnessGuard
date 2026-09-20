# M4 第二批复验 轮A（管理员）：控制台模式——estats 降级 / 归因竞态 / probe 长命句柄 / 场景回归
# bash 侧轮询 roundA.log 出现结束标记；产物 target\verify-m4b\
$ErrorActionPreference = 'Continue'
$root = "D:\develop\runlefei\HarnessGuard"
$v    = Join-Path $root "target\verify-m4b"
$exe  = Join-Path $root "target\release\harnessguard.exe"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundA.log" -Append }

& $R "== 轮A 开始（控制台模式）=="
Stop-Process -Name harnessguard -Force -ErrorAction SilentlyContinue
Start-Sleep 2

# 服务进程（控制台模式，debug 日志）
$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process $exe -ArgumentList "run", "$v\config.toml" -WorkingDirectory $v `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$v\svc.out.log" -RedirectStandardError "$v\svc.err.log"
Start-Sleep 4
$token = $null
try { $token = (Select-String -Path "$v\svc.out.log" -Pattern 'token=([0-9a-f]+)').Matches[0].Groups[1].Value } catch {}
if (-not $token) { & $R "!! 服务未产出 token"; & $R "== 轮A结束（失败）=="; exit 1 }
& $R "[启动] token=$token pid=$($svc.Id)"
$H = @{ Authorization = "Bearer $token" }

# ---------- 1) probe 长命句柄（期望 tried/hit ≥1：句柄存活 6s > ETW 投递延迟） ----------
& $R "[probe] 长命句柄：fake_harness 树内 powershell OpenRead repo\main.rs 保持 6s"
Push-Location $v
& "$v\fake_harness.exe" /c "powershell -NoProfile -ExecutionPolicy Bypass -File $v\longhold.ps1" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$st = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status"
& $R ("[probe] 长命后：tried={0} hit={1}（期望 tried≥1 且 hit≥1）" -f $st.source.file_probe_tried, $st.source.file_probe_hit)
# 短命对照（第一批结论：短命句柄探测不出，hit 不必然增长）
Push-Location $v
& "$v\fake_harness.exe" /c "type repo\main.rs" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2
$st = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status"
& $R ("[probe] 短命对照后：tried={0} hit={1} resolved={2} unknown={3}" -f $st.source.file_probe_tried, $st.source.file_probe_hit, $st.source.file_resolved, $st.source.file_unknown)

# ---------- 2) 场景 C：estats 降级 + send 主路径判定（阈值 1MB，POST 8MB） ----------
& $R "[场景C] 树内 curl POST 8MB → httpbin.org（阈值 1MB）"
Push-Location $v
& "$v\fake_harness.exe" /c "curl -s -m 40 --data-binary @big.bin http://httpbin.org/post" 2>&1 | Out-Null
Pop-Location
Start-Sleep 8
# estats 降级：每连接仅一条 warn（Set rc≠0 → 跳过后续轮询），无逐秒刷屏
$estWarn = @(Select-String -Path "$v\svc.out.log" -Pattern 'estats 不可用，该连接跳过后续轮询')
$estConns = @($estWarn | ForEach-Object { ($_.Line -split 'conn=')[1] -split ' ' | Select-Object -First 1 } | Sort-Object -Unique)
& $R ("[estats] 降级告警行数={0} 去重连接数={1}（期望 ≥1 且 行数≈连接数：每连接一次）" -f $estWarn.Count, $estConns.Count)
if ($estWarn.Count -gt 0) { & $R ("[estats] 首条：{0}" -f $estWarn[0].Line.Trim()) }
$oldRc = @(Select-String -Path "$v\svc.out.log" -Pattern 'Set\(v4\) rc=|Get rc=.*保留登记下轮重试').Count
& $R ("[estats] 旧格式 rc 刷屏行={0}（期望 0：降级后不再空调用）" -f $oldRc)
$vs = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/verdicts?limit=20"
$net = @($vs | Where-Object rule_id -eq 'net-threshold')
& $R ("[场景C] net-threshold 判定={0} 条（send 主路径，期望 ≥1）" -f $net.Count)
if ($net.Count -gt 0) { & $R ("[场景C] 首条：{0}" -f $net[0].evidence.summary) }

# ---------- 3) 归因竞态（期望：缓存归因，pid 非 0，cmdline 附 detail） ----------
$origEnabled = ((wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true')
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true | Out-Null
Start-Sleep 3
& $R "[归因] 树内 schtasks /create（发起 cmd 先于 106 退出 → 期望缓存归因）"
Push-Location $v
& "$v\fake_harness.exe" /c "schtasks /create /tn HG-M4B-R1 /tr cmd /sc once /st 23:59 /f" 2>&1 | Out-Null
Pop-Location
Start-Sleep 6
$schedLines = @(Select-String -Path "$v\svc.out.log" -Pattern '\[持久化\] 计划任务')
& $R ("[归因] [持久化] 行数={0}" -f $schedLines.Count)
$schedLines | Select-Object -Last 2 | ForEach-Object { & $R ("[归因] {0}" -f $_.Line.Trim()) }
schtasks /delete /tn HG-M4B-R1 /f 2>$null | Out-Null
wevtutil sl Microsoft-Windows-TaskScheduler/Operational "/e:$(if ($origEnabled) {'true'} else {'false'})" | Out-Null
& $R "[归因] 通道已还原（原状态 enabled=$origEnabled）"

# ---------- 4) .git 读判定回归（4663 未启用，走 ETW 路径或 unknown——如实记录） ----------
Push-Location $v
& "$v\fake_harness.exe" /c "type repo\.git\config" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$vs2 = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/verdicts?limit=50"
$git = @($vs2 | Where-Object rule_id -eq 'git-dir')
& $R ("[.git] git-dir 判定={0} 条（ETW 路径，短命句柄维持已知缺口——轮C 用 4663 验证）" -f $git.Count)

# ---------- 5) 汇总 ----------
$st = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status"
& $R ("[汇总] verdicts={0} kills={1} dropped_conns={2} ips_blocked={3} probe tried/hit={4}/{5}" -f `
    $st.engine.verdicts, $st.engine.kills, $st.engine.connections_dropped, $st.engine.ips_blocked, `
    $st.source.file_probe_tried, $st.source.file_probe_hit)
$vs3 = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/verdicts?limit=100"
& $R ("[汇总] 判定分布：{0}" -f ((($vs3 | Group-Object rule_id | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' ')))

Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$left = (logman query -ets 2>$null | Out-String) -match 'HarnessGuard'
& $R ("[清场] 控制台强杀后 ETW 残留={0}（服务启动自清，如实记录）" -f $left)
& $R "== 轮A结束 =="

