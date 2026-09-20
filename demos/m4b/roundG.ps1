# M4 第二批复验 轮G（管理员）：XML 引号修复后 4663 全链路收口（服务模式判定为证）+ 最终还原
$ErrorActionPreference = 'Continue'
$v    = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$root = "D:\develop\runlefei\HarnessGuard"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundG.log" -Append }

& $R "== 轮G 开始（4663 收口）=="
Copy-Item "$root\target\release\harnessguard.exe" "$v\inst2\harnessguard.exe" -Force

# 1) 安装 + enable + 重启
Set-Location "$v\inst2"
(& "$v\inst2\harnessguard.exe" install) 2>&1 | Select-String 'RUNNING|失败|警告' | ForEach-Object { & $R "[install] $_" }
(& "$v\inst2\harnessguard.exe" enable-file-audit "$v\repo\.git") 2>&1 | Select-String '已启用|失败' | ForEach-Object { & $R "[enable] $_" }
sc.exe stop HarnessGuard | Out-Null; Start-Sleep 4
sc.exe start HarnessGuard | Out-Null; Start-Sleep 6
& $R ("[状态] {0}" -f ((sc.exe query HarnessGuard | Select-String 'STATE') -join ' ').Trim())

# 2) 树内读 .git（判定为证）
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
& $R ("[判定] git-dir={0} 条" -f $git.Count)
$git | Select-Object -First 2 | ForEach-Object { & $R ("[判定] action={0} pid={1} {2}" -f $_.action, $_.pid, $_.evidence.summary) }
$st = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status"
& $R ("[RSS] WorkingSet={0:N1}MB（4663 运行态）" -f ((Get-Process harnessguard).WorkingSet64/1MB))

# 3) disable + 卸载 + 终态还原
(& "$v\inst2\harnessguard.exe" disable-file-audit "$v\repo\.git") 2>&1 | Select-String '已停用|失败' | ForEach-Object { & $R "[disable] $_" }
$polOff = (auditpol /get /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' 2>&1 | Out-String)
& $R ("[还原] auditpol：{0}" -f (($polOff -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^系统|^类别|^---|^$' }) -join ' ; ').Trim())
$aceN = (Get-Acl -Audit "$v\repo\.git").GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]).Count
& $R ("[还原] SACL ACE={0}" -f $aceN)
(& "$v\inst2\harnessguard.exe" uninstall) 2>&1 | ForEach-Object { & $R "[uninstall] $_" }
foreach ($s in @('HarnessGuard','HarnessGuardDns','HarnessGuardSched')) { logman stop $s -ets 2>$null | Out-Null }
$etw = (logman query -ets 2>$null | Out-String) -match 'HarnessGuard'
$svcq = (((sc.exe query HarnessGuard) 2>&1 | Out-String) -match '1060')
$tsch = (wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true'
& $R ("[终态] ETW残留={0} 服务1060={1} TaskScheduler通道={2}（期望 False/True/False）" -f $etw, $svcq, $tsch)
& $R "== 轮G结束 =="

