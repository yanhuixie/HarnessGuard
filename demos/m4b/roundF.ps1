# M4 第二批复验 轮F（管理员）：4663 消费端断点定位（控制台 debug 日志）
$ErrorActionPreference = 'Continue'
$v    = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$root = "D:\develop\runlefei\HarnessGuard"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundF.log" -Append }

& $R "== 轮F 开始（4663 消费端定位）=="
Copy-Item "$root\target\release\harnessguard.exe" "$v\inst2\harnessguard.exe" -Force

# 1) enable（系统侧：auditpol 0CCE921D + SACL + config enabled）
Set-Location "$v\inst2"
(& "$v\inst2\harnessguard.exe" enable-file-audit "$v\repo\.git") 2>&1 | ForEach-Object { & $R "[enable] $_" }

# 2) 控制台模式（debug 日志直落文件）
$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process "$v\inst2\harnessguard.exe" -ArgumentList "run", "$v\inst2\config.toml" -WorkingDirectory "$v\inst2" `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$v\diagF.out.log" -RedirectStandardError "$v\diagF.err.log"
Start-Sleep 5
$sub = (Select-String -Path "$v\diagF.out.log" -Pattern 'file-audit.*订阅').Line
& $R ("[订阅] {0}" -f ($(if ($sub) { $sub.Trim() } else { "无" })))

# 3) 树内读 .git
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "type $v\repo\.git\config" 2>&1 | Out-Null
Pop-Location
Start-Sleep 5

# 4) 收集 4663 相关全部日志
$lines = Select-String -Path "$v\diagF.out.log" -Pattern 'file-audit'
& $R ("[4663日志] 行数={0}" -f $lines.Count)
$lines | Select-Object -First 10 | ForEach-Object { & $R ("[4663日志] {0}" -f $_.Line.Trim()) }
# 判定与文件管线
$fLines = @(Select-String -Path "$v\diagF.out.log" -Pattern '\[file\] pid=\d+ .*\.git')
& $R ("[file管线] .git 相关 [file] 行={0}" -f $fLines.Count)
$fLines | Select-Object -First 3 | ForEach-Object { & $R ("[file管线] {0}" -f $_.Line.Trim()) }

Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 2

# 5) 还原
(& "$v\inst2\harnessguard.exe" disable-file-audit "$v\repo\.git") 2>&1 | ForEach-Object { & $R "[disable] $_" }
foreach ($s in @('HarnessGuard','HarnessGuardDns','HarnessGuardSched')) { logman stop $s -ets 2>$null | Out-Null }
$etw = (logman query -ets 2>$null | Out-String) -match 'HarnessGuard'
& $R ("[还原] ETW 残留={0}；auditpol/SACL 由 disable 还原" -f $etw)
& $R "== 轮F结束 =="

