# M4 第二批复验 轮D（管理员）：probe 失败定位（诊断版 exe）+ 4663 溯源 + uninstall + 系统还原核对
$ErrorActionPreference = 'Continue'
$v   = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundD.log" -Append }

& $R "== 轮D 开始（诊断 + 卸载 + 还原）=="

# ---------- 1) 停服务 + 部署诊断版 exe ----------
sc.exe stop HarnessGuard | Out-Null
Start-Sleep 5
Copy-Item "D:\develop\runlefei\HarnessGuard\target\release\harnessguard.exe" "$v\inst2\harnessguard.exe" -Force
& $R ("[部署] 诊断版 exe 已部署（含 probe 失败原因日志）")

# ---------- 2) 控制台诊断：probe 失败定位 ----------
$env:RUST_LOG = 'info,hg_plat_win=debug'
$svc = Start-Process "$v\inst2\harnessguard.exe" -ArgumentList "run", "$v\inst2\config.toml" -WorkingDirectory "$v\inst2" `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$v\diag.out.log" -RedirectStandardError "$v\diag.err.log"
Start-Sleep 5
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Start-Sleep 2
& "$v\inst2\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Pop-Location
Start-Sleep 4
Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$diag = Select-String -Path "$v\diag.out.log" -Pattern '\[probe\]'
& $R ("[probe诊断] [probe] 行数={0}" -f $diag.Count)
$diag | Group-Object { ($_.Line -split '\[probe\] ')[1] -replace '[0-9a-f]{6,}','<hex>' -replace 'st=[^ ]+','st=<nt>' } | Sort-Object Count -Descending | ForEach-Object {
    & $R ("[probe诊断] x{0} {1}" -f $_.Count, $_.Name.Trim())
}
$stLine = (Select-String -Path "$v\diag.out.log" -Pattern 'probe').Line
$hitLines = @(Select-String -Path "$v\diag.out.log" -Pattern 'file-audit')
& $R ("[probe诊断] 附：file-audit 行={0}" -f $hitLines.Count)

# ---------- 3) 4663 溯源：Security 日志里到底有没有 4663 ----------
$q = 'wevtutil qe Security /q:"*[System[EventID=4663]]" /c:6 /rd:true /f:text /e:ns'
$ev4663 = (cmd /c $q) 2>&1 | Out-String
& $R "[4663] Security 日志最近 4663（时间/对象）："
($ev4663 -split "Event\[")[1..([Math]::Min(6, ($ev4663 -split "Event\[").Count-1))] | ForEach-Object {
    $tm = ([regex]::Match($_, 'Date: ([^\r\n]+)')).Groups[1].Value
    $ob = ([regex]::Match($_, 'ObjectName:\s*\r?\n\s*([^\r\n]+)')).Groups[1].Value
    if (-not $ob) { $ob = ([regex]::Match($_, '  对象名:\s*([^\r\n]+)')).Groups[1].Value }
    & $R ("[4663] {0} {1}" -f $tm, $ob)
}
# 轮C type 时段（09:25:36-42 本地 = 01:25 UTC）是否有 .git\config 的 4663
$gitEv = ($ev4663 | Select-String '\.git').Matches.Count
& $R ("[4663] 最近 6 条中含 .git 的条数={0}（0 = auditpol/SACL 未生效 → 启用端问题；>0 = 消费端问题）" -f $gitEv)

# ---------- 4) auditpol File System 全文（子类别 GUID 与名称双查） ----------
& $R "[auditpol] GUID 查询全文："
(auditpol /get /subcategory:'{0CCE9216-69AE-11D9-BED3-505054503030}' 2>&1) | ForEach-Object { & $R "[auditpol/GUID] $_" }
& $R "[auditpol] 名称查询全文："
(auditpol /get /subcategory:'文件系统' 2>&1) | ForEach-Object { & $R "[auditpol/名称] $_" }

# ---------- 5) uninstall（正常 → 1060 二次） ----------
$un = (& "$v\inst2\harnessguard.exe" uninstall) 2>&1
$un | ForEach-Object { & $R "[uninstall] $_" }
Start-Sleep 2
& $R ("[uninstall] sc query：{0}" -f (((sc.exe query HarnessGuard) 2>&1 | Out-String) -match '1060'))
& $R ("[uninstall] web-token 已删={0}" -f (-not (Test-Path "$v\inst2\web-token.txt")))
& $R "[uninstall] 二次执行（1060 分支 + 残留清理路径）："
$un2 = (& "$v\inst2\harnessguard.exe" uninstall) 2>&1
$un2 | ForEach-Object { & $R "[uninstall2] $_" }

# ---------- 6) 系统还原核对 ----------
$GUID = '{0CCE9216-69AE-11D9-BED3-505054503030}'
$polNow = (auditpol /get /subcategory:$GUID 2>&1 | Out-String)
& $R ("[还原] auditpol File System：{0}" -f (($polNow -split "`n" | Where-Object { $_ -match '\S' }) -join ' ; ').Trim())
$aclEnd = (Get-Acl -Audit "$v\repo\.git" -ErrorAction SilentlyContinue).GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]).Count
& $R ("[还原] .git SACL ACE={0}（期望 0）" -f $aclEnd)
$tsch = (wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Out-String) -match 'enabled: true'
& $R ("[还原] TaskScheduler 通道 enabled={0}（期望 False）" -f $tsch)
$task = (schtasks /query /tn HG-M4B-R1 2>&1 | Out-String) -match 'HG-M4B'
& $R ("[还原] 计划任务 HG-M4B-R1 存在={0}（期望 False）" -f $task)
$etw = (logman query -ets 2>$null | Out-String) -match 'HarnessGuard'
& $R ("[还原] ETW 会话残留={0}（期望 False——卸载走 stop 优雅停机）" -f $etw)
$svcLeft = Get-Process harnessguard -ErrorAction SilentlyContinue
& $R ("[还原] harnessguard 进程残留={0}" -f ($null -ne $svcLeft))
& $R "== 轮D结束 =="

