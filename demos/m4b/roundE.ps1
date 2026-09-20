# M4 第二批复验 轮E（管理员）：修 GUID 后 4663 全往返重验 + probe 命中重验 + 系统还原
$ErrorActionPreference = 'Continue'
$v    = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$root = "D:\develop\runlefei\HarnessGuard"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundE.log" -Append }

& $R "== 轮E 开始（GUID 修正重验）=="

# ---------- 1) 确定 File System 子类别 GUID：本机枚举优先，回退外部多源一致的 0CCE921D ----------
$xml = (auditpol /list /subcategory /r) 2>&1 | Out-String
($xml -split "`r?`n" | Select-String '0CCE92') | Select-Object -First 12 | ForEach-Object { & $R "[GUID表] $_" }
$fsGuid = ([regex]::Match($xml, '(?i)GUID=\{"?([0-9A-Fa-f-]{36})"?\}[^>]*?Name="(?:File System|文件系统)"')).Groups[1].Value
if (-not $fsGuid) { $fsGuid = '0CCE921D-69AE-11D9-BED3-505054503030'; & $R "[GUID] 枚举未命中，回退外部多源一致值 0CCE921D" }
# 确认：/get 该 GUID 须显示"文件系统"
$check = (auditpol /get /subcategory:"{$fsGuid}" 2>&1 | Out-String)
if ($check -notmatch '文件系统') { & $R "[GUID] 验证失败：/get {$fsGuid} 未显示文件系统，中止"; & $R "== 轮E结束（GUID 验证失败）=="; exit 1 }
& $R ("[GUID] 确认 File System GUID={0}（原代码 0CCE9216 实测映射注销——错误）" -f $fsGuid)

# ---------- 2) 现场修代码常量并重编（无 BOM 写回，防 rustc 源文件 BOM 问题） ----------
$src = [IO.File]::ReadAllText("$root\crates\hg-plat-win\src\audit_setup.rs")
$srcNew = $src -replace '\{0CCE9216-69AE-11D9-BED3-505054503030\}', "{$fsGuid}"
if ($src -eq $srcNew) { & $R "[GUID] 代码替换未命中（常量已是正确值？）" }
else {
    [IO.File]::WriteAllText("$root\crates\hg-plat-win\src\audit_setup.rs", $srcNew)
    & $R "[GUID] audit_setup.rs 常量已替换 → cargo build --release"
    Push-Location $root
    $build = (cargo build --release) 2>&1 | Out-String
    Pop-Location
    if ($build -match 'error') { & $R "[构建] 失败：$build"; & $R "== 轮E结束（构建失败）=="; exit 1 }
    & $R "[构建] release 构建成功"
}

# ---------- 3) 重装服务（新 exe：GUID 修正 + probe 回退 SAME_ACCESS） ----------
Copy-Item "$root\target\release\harnessguard.exe" "$v\inst2\harnessguard.exe" -Force
$t0 = Get-Date
$ins = (& "$v\inst2\harnessguard.exe" install) 2>&1
& $R ("[install] 耗时 {0:N1}s" -f ((Get-Date)-$t0).TotalSeconds)
$ins | ForEach-Object { & $R "[install] $_" }
Start-Sleep 3
& $R ("[install] 状态：{0}" -f ((sc.exe query HarnessGuard | Select-String 'STATE') -join ' ').Trim())

# ---------- 4) probe 命中重验（SAME_ACCESS 回退后，第一批同场景 1/2） ----------
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

# ---------- 5) 4663 全往返（正确 GUID） ----------
Set-Location "$v\inst2"
$en = (& "$v\inst2\harnessguard.exe" enable-file-audit "$v\repo\.git") 2>&1
$en | ForEach-Object { & $R "[C/enable] $_" }
$pol = (auditpol /get /subcategory:"{$fsGuid}" 2>&1 | Out-String)
& $R ("[C] auditpol（正确 GUID 查询）：{0}" -f (($pol -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^系统|^类别|^---|^$' }) -join ' ; ').Trim())
sc.exe stop HarnessGuard | Out-Null
Start-Sleep 4
sc.exe start HarnessGuard | Out-Null
Start-Sleep 6
$today = Get-Date -Format 'yyyy-MM-dd'
$svclog = "$v\inst2\logs\harnessguard.log.$today"
$subLine = (Select-String -Path $svclog -Pattern 'file-audit.*订阅已建立' | Select-Object -Last 1).Line
& $R ("[C] 订阅建立：{0}" -f ($(if ($subLine) { "是" } else { "无" })))
$token = (Get-Content "$v\inst2\web-token.txt" -Raw).Trim()
$H = @{ Authorization = "Bearer $token" }
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "type $v\repo\.git\config" 2>&1 | Out-Null
Start-Sleep 2
& "$v\inst2\fake_harness.exe" /c "type $v\repo\.git\config" 2>&1 | Out-Null
Pop-Location
Start-Sleep 4
$vs = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/verdicts?limit=20"
$git = @($vs | Where-Object rule_id -eq 'git-dir')
& $R ("[C] git-dir 判定={0} 条（>0 即证 4663→FileOpen→引擎链路打通）" -f $git.Count)
if ($git.Count -gt 0) { & $R ("[C] 首条：action={0} pid={1} {2}" -f $git[0].action, $git[0].pid, $git[0].evidence.summary) }
# Security 日志 4663 直接证据
$ev = (cmd /c 'wevtutil qe Security /q:"*[System[EventID=4663]]" /c:3 /rd:true /f:text /e:ns') 2>&1 | Out-String
$gitEv = ($ev | Select-String '\.git').Matches.Count
& $R ("[C] Security 最近 3 条 4663 中含 .git={0}" -f $gitEv)

# ---------- 6) disable 还原 + 卸载 + 系统终态 ----------
$dis = (& "$v\inst2\harnessguard.exe" disable-file-audit "$v\repo\.git") 2>&1
$dis | ForEach-Object { & $R "[C/disable] $_" }
$polOff = (auditpol /get /subcategory:"{$fsGuid}" 2>&1 | Out-String)
& $R ("[还原] auditpol：{0}" -f (($polOff -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^系统|^类别|^---|^$' }) -join ' ; ').Trim())
$aceN = (Get-Acl -Audit "$v\repo\.git" -ErrorAction SilentlyContinue).GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]).Count
& $R ("[还原] .git SACL ACE={0}（期望 0）" -f $aceN)
$un = (& "$v\inst2\harnessguard.exe" uninstall) 2>&1
$un | ForEach-Object { & $R "[uninstall] $_" }
# 计划任务复核（轮D 存疑：错误输出含任务名的误匹配）
$taskOut = (schtasks /query /tn HG-M4B-R1) 2>&1 | Out-String
& $R ("[还原] HG-M4B-R1 查询输出：{0}" -f ($taskOut.Trim() -replace "`r`n", ' | '))
schtasks /delete /tn HG-M4B-R1 /f 2>$null | Out-Null
# 清诊断控制台残留 ETW 会话（强杀残留为已知行为，启动自清，此处显式清干净）
foreach ($s in @('HarnessGuard','HarnessGuardDns','HarnessGuardSched')) { logman stop $s -ets 2>$null | Out-Null }
$etw = (logman query -ets 2>$null | Out-String) -match 'HarnessGuard'
& $R ("[还原] ETW 会话残留={0}（期望 False，已显式清理）" -f $etw)
$tsch = (wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true'
& $R ("[还原] TaskScheduler 通道 enabled={0}（期望 False）" -f $tsch)
$svcq = (((sc.exe query HarnessGuard) 2>&1 | Out-String) -match '1060')
& $R ("[还原] 服务 1060={0}（期望 True）" -f $svcq)
& $R "== 轮E结束 =="



