# HarnessGuard M4 第一批管理员实机复验（需管理员 PowerShell 运行）
# 复验项（M4 报告）：1 SSE 实连 / 2 场景A探测 / 3 场景C estats / 4 WFP /
#                   5 TaskScheduler / 6 服务宿主
# 产物：target\verify-m4\（svc.out.log / sse.log / wfp-*.xml / verify-result.log）
# 系统状态变更（脚本自恢复）：TaskScheduler Operational 通道临时启用、
#   HarnessGuard 服务装-验-卸、计划任务建删；结束时应全部还原。
# 说明：模拟行为全部使用正常工具用法（M1 实测教训：勿用杀软 ML 特征行为）。

$ErrorActionPreference = 'Continue'
$root  = "D:\develop\runlefei\HarnessGuard"
$demo  = Join-Path $root "target\verify-m4"
$exe   = Join-Path $root "target\release\harnessguard.exe"
$rel   = Join-Path $root "target\release"
$bind  = "127.0.0.1:8377"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$demo\verify-result.log" -Append }

& $R "== M4 复验开始 $(Get-Date) =="

# ---------- 0. 清场与造景 ----------
Stop-Process -Name harnessguard -Force -ErrorAction SilentlyContinue
Start-Sleep 1
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $demo | Out-Null
New-Item -ItemType Directory -Force -Path "$demo\repo\.git" | Out-Null
Set-Content "$demo\repo\.git\config" "[core]`nrepositoryformatversion = 0"
Set-Content "$demo\repo\.env" "SECRET=demo-secret"
Set-Content "$demo\repo\main.rs" "fn main() {}"
# 100 个小文件（burst 相对名打开——M1 unknown 重灾区）
1..100 | ForEach-Object { Set-Content "$demo\repo\src_$_.rs" "fn f$_() {}" }
fsutil file createnew "$demo\big.bin" 8388608 | Out-Null
Copy-Item "C:\Windows\System32\cmd.exe" "$demo\fake_harness.exe" -Force

# ---------- 1. 配置（阈值 5MB；fake-harness 特征；git_dir=block 同 M1） ----------
@'
[network]
upload_threshold_mb = 5
sensitive_escalation_divisor = 10

[endpoints]
allow = ["api.anthropic.com", "*.github.com"]

[files]
git_dir_action = "block"
archive_action = "block"
sensitive_patterns = [".env", ".env.*", "*_rsa", "*.pem", "*credentials*"]
archive_patterns = ["*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.7z", "*.gz", "*.zst"]

[commands]
blocked = ["git archive*", "git bundle*", "git format-patch*"]

[[processes.harness]]
name = "fake-harness"
paths = ["**/fake_harness.exe"]

[[tool_exempt]]
exe = "git"
allow_paths = [".git/**"]

[storage]
retention_days = 30
max_disk_mb = 500
db_path = "harnessguard.db"

[web]
bind = "127.0.0.1:8377"
'@ | Set-Content "$demo\config.toml" -Encoding ascii

# ---------- 2. 启动服务（控制台模式） ----------
$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process $exe -ArgumentList "run", "$demo\config.toml" -WorkingDirectory $demo `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput "$demo\svc.out.log" -RedirectStandardError "$demo\svc.err.log"
Start-Sleep 4
$token = $null
try { $token = (Select-String -Path "$demo\svc.out.log" -Pattern 'token=([0-9a-f]+)').Matches[0].Groups[1].Value } catch {}
if (-not $token) {
    & $R "[启动] FAIL：无 token。svc.out.log："; Get-Content "$demo\svc.out.log" -Tail 20 | Tee-Object -FilePath "$demo\verify-result.log" -Append
    & $R "svc.err.log："; Get-Content "$demo\svc.err.log" -Tail 20 | Tee-Object -FilePath "$demo\verify-result.log" -Append
    exit 1
}
& $R "[启动] OK token=$token pid=$($svc.Id)"
$H = @{ Authorization = "Bearer $token" }

# ETW 会话在场证据（服务运行中）
$logmanRun = (logman query -ets 2>$null | Out-String)
& $R ("[ETW] 运行中会话含 HarnessGuard：{0}" -f ($logmanRun -match 'HarnessGuard'))

# ---------- 3.【复验 1】SSE 采集启动（45s 窗口，覆盖场景 A/C/计划任务） ----------
$sseProc = Start-Process "$env:SystemRoot\System32\curl.exe" `
    -ArgumentList '-N','-s','--max-time','50',"-H","Authorization: Bearer $token",`
                  "-o","$demo\sse.log","http://$bind/api/stream" `
    -WindowStyle Hidden -PassThru
& $R "[SSE] 采集已启动（curl pid=$($sseProc.Id)，50s 窗口）"
Start-Sleep 2

# ---------- 4.【复验 2】场景 A：探测命中率 ----------
& $R "[场景A] certutil 读 .git\config（M1 同构对照，M1 为判定管线不通）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "certutil -dump $demo\repo\.git\config" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2
& $R "[场景A] burst：cmd type 循环 100 次相对名打开"
Push-Location $demo
& "$demo\fake_harness.exe" /c "for /L %i in (1,1,100) do @type repo\src_50.rs" 2>&1 | Out-Null
& "$demo\fake_harness.exe" /c "for /L %i in (1,1,50) do @type repo\main.rs" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
try {
  $st = Invoke-RestMethod -Headers $H "http://$bind/api/status"
  & $R ("[场景A] file_resolved={0} file_unknown={1} probe_tried={2} probe_hit={3}" -f `
      $st.source.file_resolved, $st.source.file_unknown, $st.source.file_probe_tried, $st.source.file_probe_hit)
} catch { & $R "[场景A] FAIL：status 查询失败 $_" }
$vs = @()
try { $vs = Invoke-RestMethod -Headers $H "http://$bind/api/verdicts?limit=50" } catch {}
$gitv = $vs | Where-Object { $_.rule_id -eq 'git-dir' }
& $R ("[场景A] git-dir 判定数={0}（M1：0——文件名解析不通）" -f @($gitv).Count)
if (@($gitv).Count -gt 0) { & $R ("[场景A] 证据示例：{0}" -f $gitv[0].evidence.summary) }

# ---------- 5.【复验 3+4】场景 C：estats 补计 + 阈值处置 + WFP ----------
& $R "[场景C] 树内 curl POST 8MB 到 httpbin.org（阈值 5MB）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "curl -s -m 40 --data-binary @big.bin http://httpbin.org/post" 2>&1 | Out-Null
Pop-Location
Start-Sleep 5
$estatsLines = @(Select-String -Path "$demo\svc.out.log" -Pattern '\[conn-estats\]')
& $R ("[场景C] [conn-estats] 差分日志行数={0}（M1：0——send 采样态无字节来源）" -f $estatsLines.Count)
if ($estatsLines.Count -gt 0) { & $R ("[场景C] 示例：{0}" -f $estatsLines[0].Line.Trim()) }
$wfpLine = (Select-String -Path "$demo\svc.out.log" -Pattern '\[wfp\] 过滤器').Line
& $R ("[场景C/WFP] 服务日志 WFP 过滤器行：{0}" -f ($(if ($wfpLine) { $wfpLine.Trim() } else { "无" })))
$blockLine = (Select-String -Path "$demo\svc.out.log" -Pattern '\[处置\] 封禁').Line
& $R ("[场景C/WFP] 封禁处置行：{0}" -f ($(if ($blockLine) { $blockLine.Trim() } else { "无" })))
$netv = $vs | Where-Object { $_.rule_id -eq 'net-threshold' }
& $R ("[场景C] net-threshold 判定数={0}" -f @($netv).Count)
# WFP 内核态核验（TTL 600s 内）
netsh wfp show sublayers file="$demo\wfp-sub-during.xml" | Out-Null
netsh wfp show filters  file="$demo\wfp-flt-during.xml" | Out-Null
& $R ("[WFP] 运行中 sublayer 含 HarnessGuard：{0}" -f ((Get-Content "$demo\wfp-sub-during.xml" -Raw) -match 'HarnessGuard'))
& $R ("[WFP] 运行中 filter 含 HarnessGuard：{0}" -f ((Get-Content "$demo\wfp-flt-during.xml" -Raw) -match 'HarnessGuard'))

# ---------- 6.【复验 5】TaskScheduler（临时启用通道，结束恢复） ----------
$origEnabled = ((wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true')
& $R ("[计划任务] 通道原状态 enabled={0}（现临时启用，结束恢复）" -f $origEnabled)
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true | Out-Null
& $R "[计划任务] 树内 fake_harness 执行 schtasks create（验证归因链第二级：cmdline 特征扫描）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "schtasks /create /tn HarnessGuardM4复验 /tr cmd /sc once /st 23:59 /f" 2>&1 | Out-Null
Pop-Location
Start-Sleep 4
$schedLog = (Select-String -Path "$demo\svc.out.log" -Pattern '\[持久化\] 计划任务').Line
& $R ("[计划任务] 服务日志：{0}" -f ($(if ($schedLog) { $schedLog.Trim() } else { "无（106 事件未流入？）" })))
try {
  $vs2 = Invoke-RestMethod -Headers $H "http://$bind/api/verdicts?limit=50"
  $pv = $vs2 | Where-Object { $_.rule_id -eq 'persistence' }
  & $R ("[计划任务] persistence 判定数={0}（RunKey 轮询关闭场景下应为 SchedTask 来源）" -f @($pv).Count)
  $pv | Select-Object -First 2 | ForEach-Object { & $R ("[计划任务] 证据：{0}" -f $_.evidence.summary) }
} catch { & $R "[计划任务] FAIL：verdicts 查询失败 $_" }
schtasks /delete /tn HarnessGuardM4复验 /f 2>$null | Out-Null
$restoreVal = "/e:$(if ($origEnabled) {'true'} else {'false'})"
wevtutil sl Microsoft-Windows-TaskScheduler/Operational $restoreVal | Out-Null
& $R ("[计划任务] 通道已恢复 {0}" -f $restoreVal)

# ---------- 7. SSE 结果与控制台强杀对照（WFP 动态过滤器应随进程消失） ----------
& $R "[SSE] 等待采集窗口结束（最长 50s）…"
Wait-Process -Id $sseProc.Id -Timeout 55 -ErrorAction SilentlyContinue
Start-Sleep 1
$sseText = ""
try { $sseText = Get-Content "$demo\sse.log" -Raw -ErrorAction Stop } catch {}
& $R ("[SSE] retry 帧：{0}；verdict 帧：{1}；audit 帧：{2}；总字节：{3}" -f `
    ($sseText -match 'retry: 3000'), ([regex]::Matches($sseText,'event: verdict').Count), `
    ([regex]::Matches($sseText,'event: audit').Count), $sseText.Length)

& $R "[对照] taskkill 强杀控制台服务（预期：WFP 过滤器随动态会话消失；ETW 会话残留——M1 教训，服务模式优雅停机做对照）"
Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 3
netsh wfp show filters file="$demo\wfp-flt-after-kill.xml" | Out-Null
netsh wfp show sublayers file="$demo\wfp-sub-after-kill.xml" | Out-Null
& $R ("[对照] 强杀后 filter 含 HarnessGuard：{0}（预期 False）" -f ((Get-Content "$demo\wfp-flt-after-kill.xml" -Raw) -match 'HarnessGuard'))
& $R ("[对照] 强杀后 sublayer 含 HarnessGuard：{0}（持久会话装配，残留为设计行为）" -f ((Get-Content "$demo\wfp-sub-after-kill.xml" -Raw) -match 'HarnessGuard'))
$logmanKill = (logman query -ets 2>$null | Out-String)
& $R ("[对照] 强杀后 ETW 会话残留：{0}（预期 True——强杀不回收；服务 sc stop 应回收）" -f ($logmanKill -match 'HarnessGuard'))

# ---------- 8.【复验 6】服务宿主 ----------
& $R "[服务] install…"
$inst = & $exe install 2>&1 | Out-String
& $R ("[服务] install 输出：{0}" -f $inst.Trim())
$qf = (sc.exe qfailure HarnessGuard 2>&1 | Out-String).Trim()
& $R ("[服务] qfailure：`n{0}" -f $qf)
sc.exe start HarnessGuard | Out-Null
$running = $false
foreach ($i in 1..15) {
  Start-Sleep 2
  $q = (sc.exe query HarnessGuard 2>&1 | Out-String)
  if ($q -match 'RUNNING') { $running = $true; break }
}
& $R ("[服务] sc start 后 RUNNING：{0}（{1}s 内）" -f $running, ($i*2))
Start-Sleep 3
$svcCfg = Test-Path "$rel\config.toml"; $svcDb = Test-Path "$rel\harnessguard.db"
$svcTok = if (Test-Path "$rel\web-token.txt") { (Get-Content "$rel\web-token.txt" -Raw).Trim() } else { "" }
& $R ("[服务] exe 目录文件：config.toml={0} db={1} web-token.txt={2}" -f $svcCfg, $svcDb, ($svcTok.Length -gt 0))
$logmanSvc = (logman query -ets 2>$null | Out-String)
& $R ("[服务] 服务模式 ETW 会话在场：{0}" -f ($logmanSvc -match 'HarnessGuard'))
if ($svcTok) {
  try {
    $st2 = Invoke-RestMethod -Headers @{ Authorization = "Bearer $svcTok" } "http://127.0.0.1:8377/api/status"
    & $R ("[服务] 服务模式 /api/status OK（uptime={0}s，进程表={1}）" -f $st2.uptime_s, $st2.procs)
  } catch { & $R ("[服务] FAIL：服务模式 status 查询失败（注意默认配置端口 8377）：{0}" -f $_.Exception.Message) }
}
& $R "[服务] 恢复策略：taskkill /f → 等 12s → 期望 SCM 自动重启"
taskkill /f /im harnessguard.exe 2>$null | Out-Null
Start-Sleep 12
$q2 = (sc.exe query HarnessGuard 2>&1 | Out-String)
& $R ("[服务] 强杀 12s 后状态含 RUNNING：{0}" -f ($q2 -match 'RUNNING'))
& $R "[服务] sc stop（优雅停机：ETW 回收 + 存储冲刷）"
sc.exe stop HarnessGuard | Out-Null
$stopped = $false
foreach ($i in 1..15) {
  Start-Sleep 2
  $q = (sc.exe query HarnessGuard 2>&1 | Out-String)
  if ($q -match 'STOPPED') { $stopped = $true; break }
}
& $R ("[服务] sc stop 后 STOPPED：{0}（{1}s 内）" -f $stopped, ($i*2))
Start-Sleep 2
$logmanStop = (logman query -ets 2>$null | Out-String)
& $R ("[服务] 优雅停机后 ETW 会话残留：{0}（预期 False——与强杀 True 对照）" -f ($logmanStop -match 'HarnessGuard'))
& $R "[服务] uninstall…"
$un = & $exe uninstall 2>&1 | Out-String
& $R ("[服务] uninstall 输出：{0}" -f $un.Trim())
$gone = ((sc.exe query HarnessGuard 2>&1 | Out-String) -match '1060')
& $R ("[服务] 卸载后 sc query 返回 1060：{0}" -f $gone)
Remove-Item "$rel\web-token.txt" -Force -ErrorAction SilentlyContinue
Remove-Item "$rel\config.toml","$rel\harnessguard.db","$rel\harnessguard.db-*" -Force -ErrorAction SilentlyContinue

& $R "== M4 复验结束 $(Get-Date) =="
& $R "结论判读见 verify-result.log 各行 PASS 证据；汇总由复验报告人工判读（避免脚本误判掩盖细节）。"
