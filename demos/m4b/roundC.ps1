# M4 第二批复验 轮C（管理员）：B2 补验（修 config 后三件套/ACL/probe/RSS）+ 4663 enable/disable 全往返
$ErrorActionPreference = 'Continue'
$v   = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundC.log" -Append }

& $R "== 轮C 开始（B2 补验 + 4663）=="

# ---------- B2-1 修正 inst2 config（轮B 资产缺陷：缺 divisor 字段） ----------
@'
[network]
upload_threshold_mb = 100
sensitive_escalation_divisor = 10

[endpoints]
allow = ["api.anthropic.com", "*.github.com"]

[files]
git_dir_action = "block"
archive_action = "block"
sensitive_patterns = [".env", ".env.*", "*_rsa", "*.pem", "*credentials*"]
archive_patterns = ["*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.7z", "*.gz", "*.zst"]

[[processes.harness]]
name = "fake-harness"
paths = ["**/fake_harness.exe"]

[storage]
retention_days = 30
max_disk_mb = 500
db_path = "harnessguard.db"

[web]
bind = "127.0.0.1:8377"
'@ | Set-Content "$v\inst2\config.toml" -Encoding ascii
# 已保护文件：先还原 Everyone 再改写（TrustedInstaller 之外 owner= Administrators 可写?）——直接尝试，失败则记录
sc.exe stop HarnessGuard | Out-Null
Start-Sleep 4
$w = $false
try { Set-Content "$v\inst2\config.toml" -Value (Get-Content "$v\inst2\config.toml" -Raw) -ErrorAction Stop; $w = $true } catch {}
& $R ("[B2] 服务停止后 config 改写={0}（ACL 保护下写权限验证）" -f $w)
sc.exe start HarnessGuard | Out-Null
Start-Sleep 6
& $R ("[B2] 服务状态：{0}" -f ((sc.exe query HarnessGuard | Select-String 'STATE') -join ' ').Trim())

# ---------- B2-2 三件套 + ACL ----------
$token = $null
try { $token = (Get-Content "$v\inst2\web-token.txt" -Raw).Trim() } catch {}
& $R ("[B2] web-token.txt 存在={0} 长度={1}（服务启动重写）" -f ($null -ne $token), $token.Length)
foreach ($f in @('config.toml','harnessguard.db','web-token.txt')) {
    $acl = (icacls "$v\inst2\$f") 2>&1 | Out-String
    $ace = ($acl -split "`n" | Where-Object { $_ -match '^\s' }) -join ' | '
    & $R ("[B2/ACL] {0}: {1}" -f $f, $ace.Trim())
}
$today = Get-Date -Format 'yyyy-MM-dd'
$svclog = "$v\inst2\logs\harnessguard.log.$today"
$selfchk = (Select-String -Path $svclog -Pattern '自保护|未受保护' | Measure-Object).Count
& $R ("[B2] 启动自检告警数={0}（期望 0：三件套均受保护）" -f $selfchk)
$lastLines = Get-Content $svclog -Tail 4 -ErrorAction SilentlyContinue
$lastLines | ForEach-Object { & $R "[B2/日志尾] $_" }

# ---------- B2-3 probe 补验（certutil，第一批同场景 1/2） ----------
$H = @{ Authorization = "Bearer $token" }
$before = (Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status").source
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Start-Sleep 2
& "$v\inst2\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$after = (Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status").source
& $R ("[B2/probe] certutil 两轮：tried {0}→{1} hit {2}→{3}（第一批同场景 hit=1/2）" -f `
    $before.file_probe_tried, $after.file_probe_tried, $before.file_probe_hit, $after.file_probe_hit)

# ---------- B2-4 RSS 首读 ----------
$proc = Get-Process harnessguard -ErrorAction SilentlyContinue | Select-Object -First 1
if ($proc) { $proc.Refresh(); & $R ("[B2/RSS] WorkingSet={0:N1}MB（预算 ≤100MB）" -f ($proc.WorkingSet64/1MB)) }

# ---------- C-1 auditpol 备份 + enable-file-audit ----------
$GUID = '{0CCE9216-69AE-11D9-BED3-505054503030}'
$polBefore = (auditpol /get /subcategory:$GUID 2>&1 | Out-String)
& $R ("[C] auditpol 原状：{0}" -f (($polBefore -split "`n" | Where-Object { $_ -match '文件系统|成功|失败' }) -join ' ; ').Trim())
Set-Location "$v\inst2"
& $R "[C] enable-file-audit（watch=repo\.git）"
$en = (& "$v\inst2\harnessguard.exe" enable-file-audit "$v\repo\.git") 2>&1
$en | ForEach-Object { & $R "[C/enable] $_" }
$polOn = (auditpol /get /subcategory:$GUID 2>&1 | Out-String)
& $R ("[C] auditpol 现在：{0}" -f (($polOn -split "`n" | Where-Object { $_ -match '文件系统|成功|失败' }) -join ' ; ').Trim())
try {
    $acl = Get-Acl -Audit "$v\repo\.git"
    $audit = $acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    & $R ("[C/SACL] 审计 ACE 数={0}（期望 ≥1：Everyone 读+写成功审计）" -f $audit.Count)
    $audit | ForEach-Object { & $R ("[C/SACL] {0} {1} {2}" -f $_.IdentityReference, $_.AuditFlags, $_.FileSystemRights) }
} catch { & $R "[C/SACL] 读取失败：$_" }

# ---------- C-2 重启服务（订阅建立） + 树内读 .git ----------
sc.exe stop HarnessGuard | Out-Null
Start-Sleep 4
sc.exe start HarnessGuard | Out-Null
Start-Sleep 6
$subLine = (Select-String -Path $svclog -Pattern 'file-audit.*订阅' | Select-Object -Last 1).Line
& $R ("[C] 订阅建立日志：{0}" -f ($(if ($subLine) { $subLine.Trim() } else { "无" })))
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
& $R ("[C] git-dir 判定={0} 条（ETW 短命 unknown 为定案 → 判定出现即证 4663 链路）" -f $git.Count)
if ($git.Count -gt 0) { & $R ("[C] 首条：action={0} pid={1} {2}" -f $git[0].action, $git[0].pid, $git[0].evidence.summary) }

# ---------- C-3 disable-file-audit 还原 ----------
$dis = (& "$v\inst2\harnessguard.exe" disable-file-audit "$v\repo\.git") 2>&1
$dis | ForEach-Object { & $R "[C/disable] $_" }
$polOff = (auditpol /get /subcategory:$GUID 2>&1 | Out-String)
& $R ("[C] auditpol 还原后：{0}" -f (($polOff -split "`n" | Where-Object { $_ -match '文件系统|成功|失败' }) -join ' ; ').Trim())
try {
    $acl2 = Get-Acl -Audit "$v\repo\.git"
    $audit2 = $acl2.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    & $R ("[C/SACL] 还原后审计 ACE 数={0}（期望 0）" -f $audit2.Count)
} catch { & $R "[C/SACL] 读取失败：$_" }
sc.exe stop HarnessGuard | Out-Null
Start-Sleep 4
sc.exe start HarnessGuard | Out-Null
Start-Sleep 6

# ---------- C-4 RSS 终读 ----------
$proc2 = Get-Process harnessguard -ErrorAction SilentlyContinue | Select-Object -First 1
if ($proc2) { $proc2.Refresh(); & $R ("[C/RSS] 终读：WorkingSet={0:N1}MB PrivateMemory={1:N1}MB" -f ($proc2.WorkingSet64/1MB), ($proc2.PrivateMemorySize64/1MB)) }
& $R "== 轮C结束 =="

