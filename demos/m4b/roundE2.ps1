# M4 第二批复验 轮E2（管理员）：GUID 已修正构建完成 → 安装/probe/4663 重验/还原
$ErrorActionPreference = 'Continue'
$v    = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$root = "D:\develop\runlefei\HarnessGuard"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundE2.log" -Append }

& $R "== 轮E2 开始（GUID 修正后重验）=="
$fsGuid = '0CCE921D-69AE-11D9-BED3-505054503030'

# ---------- 1) 安装（新 exe：GUID 0CCE921D + probe SAME_ACCESS 回退） ----------
Copy-Item "$root\target\release\harnessguard.exe" "$v\inst2\harnessguard.exe" -Force
$t0 = Get-Date
$ins = (& "$v\inst2\harnessguard.exe" install) 2>&1
& $R ("[install] 耗时 {0:N1}s" -f ((Get-Date)-$t0).TotalSeconds)
$ins | ForEach-Object { & $R "[install] $_" }
Start-Sleep 3
& $R ("[install] 状态：{0}" -f ((sc.exe query HarnessGuard | Select-String 'STATE') -join ' ').Trim())

# ---------- 2) probe 命中重验 ----------
$token = (Get-Content "$v\inst2\web-token.txt" -Raw).Trim()
$H = @{ Authorization = "Bearer $token" }
$before = (Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status").source
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Start-Sleep 2
& "$v\inst2\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$after = (Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status").source
& $R ("[probe] certutil 两轮：tried {0}→{1} hit {2}→{3}（SAME_ACCESS 回退后期望 hit≥1）" -f `
    $before.file_probe_tried, $after.file_probe_tried, $before.file_probe_hit, $after.file_probe_hit)

# ---------- 3) 4663 全往返（正确 GUID） ----------
Set-Location "$v\inst2"
$en = (& "$v\inst2\harnessguard.exe" enable-file-audit "$v\repo\.git") 2>&1
$en | ForEach-Object { & $R "[enable] $_" }
$pol = (auditpol /get /subcategory:"{$fsGuid}" 2>&1 | Out-String)
& $R ("[enable/auditpol] {0}" -f (($pol -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^系统|^类别|^---|^$' }) -join ' ; ').Trim())
$ace = (Get-Acl -Audit "$v\repo\.git" -ErrorAction SilentlyContinue).GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]).Count
& $R ("[enable/SACL] ACE={0}（期望 ≥1）" -f $ace)
sc.exe stop HarnessGuard | Out-Null
Start-Sleep 4
sc.exe start HarnessGuard | Out-Null
Start-Sleep 6
$today = Get-Date -Format 'yyyy-MM-dd'
$svclog = "$v\inst2\logs\harnessguard.log.$today"
$subLine = (Select-String -Path $svclog -Pattern 'file-audit.*订阅已建立' | Select-Object -Last 1).Line
& $R ("[4663] 订阅建立：{0}" -f ($(if ($subLine) { "是" } else { "无" })))
$token = (Get-Content "$v\inst2\web-token.txt" -Raw).Trim()
$H = @{ Authorization = "Bearer $token" }
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "type $v\repo\.git\config" 2>&1 | Out-Null
Start-Sleep 2
& "$v\inst2\fake_harness.exe" /c "type $v\repo\.git\config" 2>&1 | Out-Null
Pop-Location
Start-Sleep 5
$vs = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/verdicts?limit=20"
$git = @($vs | Where-Object rule_id -eq 'git-dir')
& $R ("[4663] git-dir 判定={0} 条（>0 即证 4663→FileOpen→引擎链路打通）" -f $git.Count)
if ($git.Count -gt 0) { & $R ("[4663] 首条：action={0} pid={1} {2}" -f $git[0].action, $git[0].pid, $git[0].evidence.summary) }
$ev = (cmd /c 'wevtutil qe Security /q:"*[System[EventID=4663]]" /c:3 /rd:true /f:text /e:ns') 2>&1 | Out-String
$gitEv = ($ev | Select-String '\.git').Matches.Count
& $R ("[4663] Security 最近 3 条 4663 中含 .git={0}" -f $gitEv)

# ---------- 4) RSS（4663 运行态） ----------
$proc = Get-Process harnessguard -ErrorAction SilentlyContinue | Select-Object -First 1
if ($proc) { $proc.Refresh(); & $R ("[RSS] WorkingSet={0:N1}MB（预算 ≤100MB）" -f ($proc.WorkingSet64/1MB)) }

# ---------- 5) disable 还原 + 卸载 + 系统终态 ----------
$dis = (& "$v\inst2\harnessguard.exe" disable-file-audit "$v\repo\.git") 2>&1
$dis | ForEach-Object { & $R "[disable] $_" }
$polOff = (auditpol /get /subcategory:"{$fsGuid}" 2>&1 | Out-String)
& $R ("[还原/auditpol] {0}" -f (($polOff -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^系统|^类别|^---|^$' }) -join ' ; ').Trim())
$aceN = (Get-Acl -Audit "$v\repo\.git" -ErrorAction SilentlyContinue).GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]).Count
& $R ("[还原/SACL] ACE={0}（期望 0）" -f $aceN)
$un = (& "$v\inst2\harnessguard.exe" uninstall) 2>&1
$un | ForEach-Object { & $R "[uninstall] $_" }
$taskOut = (schtasks /query /tn HG-M4B-R1) 2>&1 | Out-String
& $R ("[还原] HG-M4B-R1 查询：{0}" -f ($taskOut.Trim() -replace "`r`n", ' | '))
schtasks /delete /tn HG-M4B-R1 /f 2>$null | Out-Null
foreach ($s in @('HarnessGuard','HarnessGuardDns','HarnessGuardSched')) { logman stop $s -ets 2>$null | Out-Null }
$etw = (logman query -ets 2>$null | Out-String) -match 'HarnessGuard'
& $R ("[还原] ETW 会话残留={0}（期望 False）" -f $etw)
$tsch = (wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true'
& $R ("[还原] TaskScheduler 通道 enabled={0}（期望 False）" -f $tsch)
$svcq = (((sc.exe query HarnessGuard) 2>&1 | Out-String) -match '1060')
& $R ("[还原] 服务 1060={0}（期望 True）" -f $svcq)
& $R "== 轮E2结束 =="

