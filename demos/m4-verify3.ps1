# M4 复验第三轮（管理员）：验证 GUID/探测/estats 三项修复 + SSE verdict 帧
$ErrorActionPreference = 'Continue'
$root = "D:\develop\runlefei\HarnessGuard"
$demo = Join-Path $root "target\verify-m4"
$exe  = Join-Path $root "target\release\harnessguard.exe"
$bind = "127.0.0.1:8377"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$demo\verify3.log" -Append }

& $R "== 第三轮（修复验证）开始 =="
Stop-Process -Name harnessguard -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Copy-Item "$demo\svc.out.log" "$demo\svc.round2.log" -Force -ErrorAction SilentlyContinue
$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process $exe -ArgumentList "run", "$demo\config.toml" -WorkingDirectory $demo `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$demo\svc.out.log" -RedirectStandardError "$demo\svc.err.log"
Start-Sleep 4
$token = (Select-String -Path "$demo\svc.out.log" -Pattern 'token=([0-9a-f]+)').Matches[0].Groups[1].Value
& $R "[启动] token=$token"
$H = @{ Authorization = "Bearer $token" }

# SSE 采集（覆盖全场景，60s 窗）
$sseProc = Start-Process "$env:SystemRoot\System32\curl.exe" `
    -ArgumentList '-N','-s','--max-time','60',"-H","Authorization: Bearer $token",`
                  "-o","$demo\sse5.log","http://$bind/api/stream" -WindowStyle Hidden -PassThru
Start-Sleep 2

# 1) 场景 A（修复验证：Read 事件也探测）
Push-Location $demo
& "$demo\fake_harness.exe" /c "type repo\.git\config" 2>&1 | Out-Null
Start-Sleep 2
& "$demo\fake_harness.exe" /c "type repo\.env" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$st = Invoke-RestMethod -Headers $H "http://$bind/api/status"
& $R ("[场景A] resolved={0} unknown={1} probe_tried={2} probe_hit={3}" -f `
    $st.source.file_resolved, $st.source.file_unknown, $st.source.file_probe_tried, $st.source.file_probe_hit)
$gitFile = (Select-String -Path "$demo\svc.out.log" -Pattern '\[file\].*\.git').Line
& $R ("[场景A] .git 进入 [file] 管线：{0}" -f ($(if ($gitFile) { $gitFile.Trim() } else { "无" })))

# 2) TaskScheduler（修复验证：正确 GUID）
$origEnabled = ((wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true')
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true | Out-Null
Start-Sleep 3
Push-Location $demo
& "$demo\fake_harness.exe" /c "schtasks /create /tn HG-M4-R3 /tr cmd /sc once /st 23:59 /f" 2>&1 | Out-Null
Pop-Location
Start-Sleep 5
$schedLog = (Select-String -Path "$demo\svc.out.log" -Pattern '\[持久化\] 计划任务').Line
& $R ("[计划任务] 服务日志：{0}" -f ($(if ($schedLog) { $schedLog.Trim() } else { "无（仍失败）" })))
schtasks /delete /tn HG-M4-R3 /f 2>$null | Out-Null
wevtutil sl Microsoft-Windows-TaskScheduler/Operational "/e:$(if ($origEnabled) {'true'} else {'false'})" | Out-Null

# 3) 场景 C（SSE verdict 帧 + estats Set rc 诊断）
Push-Location $demo
& "$demo\fake_harness.exe" /c "curl -s -m 40 --data-binary @big.bin http://httpbin.org/post" 2>&1 | Out-Null
Pop-Location
Start-Sleep 5
$setRc = (Select-String -Path "$demo\svc.out.log" -Pattern '\[conn-estats\] Set\(v4\) rc=').Line
& $R ("[estats] Set 返回值日志：{0}" -f ($(if ($setRc) { $setRc.Trim() } else { "无（Set 成功=rc 0？）" })))
$okLines = @(Select-String -Path "$demo\svc.out.log" -Pattern 'conn-estats.*\+\d+B').Count
$rc50 = @(Select-String -Path "$demo\svc.out.log" -Pattern 'conn-estats.*rc=50').Count
& $R ("[estats] 差分成功行={0} rc=50 行={1}" -f $okLines, $rc50)

# SSE 收口
Wait-Process -Id $sseProc.Id -Timeout 65 -ErrorAction SilentlyContinue
Start-Sleep 1
$sse5 = ""
try { $sse5 = Get-Content "$demo\sse5.log" -Raw } catch {}
& $R ("[SSE] retry:{0} verdict帧:{1} audit帧:{2} 总字节:{3}" -f `
    ($sse5 -match 'retry: 3000'), ([regex]::Matches($sse5,'event: verdict').Count), `
    ([regex]::Matches($sse5,'event: audit').Count), $sse5.Length)
$vs = Invoke-RestMethod -Headers $H "http://$bind/api/verdicts?limit=100"
& $R ("[判定汇总] {0}" -f ((($vs | Group-Object rule_id | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' ')))
$vs | Where-Object { $_.rule_id -in 'git-dir','persistence','net-threshold' } | Select-Object -First 4 | ForEach-Object {
  & $R ("[判定详情] {0} {1} pid={2} {3}" -f $_.rule_id, $_.action, $_.pid, $_.evidence.summary)
}

Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$left = (logman query -ets 2>$null | Out-String) -match 'HarnessGuard'
& $R ("[清场] 强杀后 ETW 残留={0}（服务启动时会自清，如实记录）" -f $left)
& $R "== 第三轮结束 =="
