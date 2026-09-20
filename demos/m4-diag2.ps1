# M4 复验二轮诊断（管理员）：SSE 复现 / TaskScheduler 延迟重试 / 场景A type 重测 / estats 字节来源
$ErrorActionPreference = 'Continue'
$root = "D:\develop\runlefei\HarnessGuard"
$demo = Join-Path $root "target\verify-m4"
$exe  = Join-Path $root "target\release\harnessguard.exe"
$bind = "127.0.0.1:8377"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$demo\diag2.log" -Append }

& $R "== 二轮诊断开始 =="
Stop-Process -Name harnessguard -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Copy-Item "$demo\svc.out.log" "$demo\svc.round1.log" -Force   # 一轮日志存档
$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process $exe -ArgumentList "run", "$demo\config.toml" -WorkingDirectory $demo `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$demo\svc.out.log" -RedirectStandardError "$demo\svc.err.log"
Start-Sleep 4
$token = (Select-String -Path "$demo\svc.out.log" -Pattern 'token=([0-9a-f]+)').Matches[0].Groups[1].Value
& $R "[启动] token=$token"
$H = @{ Authorization = "Bearer $token" }

# ---------- 1. SSE 复现（-v 全过程） ----------
& $R "[SSE] Bearer 形式 curl -v 复现（8s）"
& "$env:SystemRoot\System32\curl.exe" -v -N --max-time 8 -H "Authorization: Bearer $token" `
    "http://$bind/api/stream" -o "$demo\sse2.log" 2> "$demo\sse2.verbose.log"
& $R ("[SSE] exit=$LASTEXITCODE body字节={0}" -f (Get-Item "$demo\sse2.log" -ErrorAction SilentlyContinue).Length)
Get-Content "$demo\sse2.verbose.log" -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object { & $R ("[SSE-v] {0}" -f $_) }
& $R "[SSE] query token 形式（8s）"
& "$env:SystemRoot\System32\curl.exe" -s -N --max-time 8 "http://$bind/api/stream?token=$token" -o "$demo\sse3.log"
& $R ("[SSE] query 形式 body字节={0}" -f (Get-Item "$demo\sse3.log" -ErrorAction SilentlyContinue).Length)
& $R "[SSE] 期间触发一次判定（type .git\hooks\pre-commit，注入面）供 SSE 推送观测"
# 拍板记录 12：.git 工作流面（config 读等）已放行，场景 A 样本须用注入面
New-Item -ItemType File -Force -Path "$demo\repo\.git\hooks\pre-commit" | Out-Null
Push-Location $demo
& "$demo\fake_harness.exe" /c "type repo\.git\hooks\pre-commit" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
& "$env:SystemRoot\System32\curl.exe" -s -N --max-time 6 -H "Authorization: Bearer $token" "http://$bind/api/stream" -o "$demo\sse4.log"
& $R ("[SSE] 判定后窗口 body字节={0}（应含 retry/verdict/audit 帧）" -f (Get-Item "$demo\sse4.log" -ErrorAction SilentlyContinue).Length)
try { $sse4 = Get-Content "$demo\sse4.log" -Raw } catch { $sse4 = "" }
& $R ("[SSE] retry:{0} verdict:{1} audit:{2}" -f ($sse4 -match 'retry: 3000'), ([regex]::Matches($sse4,'event: verdict').Count), ([regex]::Matches($sse4,'event: audit').Count))

# ---------- 2. 场景 A 重测（type 直读，无 certutil 引号坑） ----------
# 注入面样本（hooks 读）：工作流面（config/objects 等）已按拍板记录 12 放行
New-Item -ItemType File -Force -Path "$demo\repo\.git\hooks\pre-commit" | Out-Null
Push-Location $demo
& "$demo\fake_harness.exe" /c "type repo\.git\hooks\pre-commit" 2>&1 | Out-Null
& "$demo\fake_harness.exe" /c "type repo\.env" 2>&1 | Out-Null
& "$demo\fake_harness.exe" /c "for /L %i in (1,1,60) do @type repo\src_1.rs" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$st = Invoke-RestMethod -Headers $H "http://$bind/api/status"
& $R ("[场景A] resolved={0} unknown={1} probe_tried={2} probe_hit={3}" -f `
    $st.source.file_resolved, $st.source.file_unknown, $st.source.file_probe_tried, $st.source.file_probe_hit)
$gitHit = (Select-String -Path "$demo\svc.out.log" -Pattern '\[file\].*\.git').Line
& $R ("[场景A] .git 相关 [file] 行：{0}" -f ($(if ($gitHit) { $gitHit.Trim() } else { "无" })))
$probeFileHit = (Select-String -Path "$demo\svc.out.log" -Pattern 'file-unknown.*obj=(?!0)').Line
& $R ("[场景A] [file-unknown] 样例：{0}" -f ($(if ($probeFileHit) { $probeFileHit.Trim() } else { "无" })))

# ---------- 3. TaskScheduler：enable 后延迟 6s 再建 ----------
$origEnabled = ((wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true')
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true | Out-Null
& $R "[计划任务] 通道已启用，等待 6s 让 svchost 重配置 provider…"
Start-Sleep 6
Push-Location $demo
& "$demo\fake_harness.exe" /c "schtasks /create /tn HG-M4-RETEST /tr cmd /sc once /st 23:59 /f" 2>&1 | ForEach-Object { & $R ("[schtasks] {0}" -f $_) }
Pop-Location
Start-Sleep 5
$schedLog = (Select-String -Path "$demo\svc.out.log" -Pattern '\[持久化\] 计划任务').Line
& $R ("[计划任务] 服务日志：{0}" -f ($(if ($schedLog) { $schedLog.Trim() } else { "无" })))
schtasks /delete /tn HG-M4-RETEST /f 2>$null | Out-Null
wevtutil sl Microsoft-Windows-TaskScheduler/Operational "/e:$(if ($origEnabled) {'true'} else {'false'})" | Out-Null
& $R "[计划任务] 通道已恢复"

# ---------- 4. estats 字节来源判定（[net] send 事件字节合计） ----------
$sendBytes = 0
(Select-String -Path "$demo\svc.out.log" -Pattern '\[net\] op=10').Line | ForEach-Object {
  if ($_ -match 'op=10.*') { $sendBytes++ }
}
& $R ("[来源] 本窗口 [net] op=10(send) 事件行数={0}（若≈38 与 conn-estats 轮次相当，则 send 活跃；结合 rc=50 全败判定字节来源）" -f $sendBytes)
$rc50 = @(Select-String -Path "$demo\svc.out.log" -Pattern 'conn-estats.*rc=50').Count
$okLines = @(Select-String -Path "$demo\svc.out.log" -Pattern 'conn-estats.*\+\d+B').Count
& $R ("[来源] conn-estats：rc=50 行={0}，差分成功行={1}" -f $rc50, $okLines)

# ---------- 5. 最终判定统一查询（修一轮时序 bug） ----------
try {
  $vs = Invoke-RestMethod -Headers $H "http://$bind/api/verdicts?limit=100"
  & $R ("[判定汇总] 共 {0} 条" -f @($vs).Count)
  $vs | Group-Object rule_id | ForEach-Object { & $R ("[判定汇总] {0} x{1}" -f $_.Name, $_.Count) }
} catch { & $R "[判定汇总] FAIL $_" }

Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
& $R "== 二轮诊断结束 =="
