# M4 第二批复验 轮I（管理员）：4663→判定 收口（长命读进程绕过投递延迟竞态）
$ErrorActionPreference = 'Continue'
$v    = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$root = "D:\develop\runlefei\HarnessGuard"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundI.log" -Append }

& $R "== 轮I 开始（4663 判定收口）=="
Set-Location "$v\inst2"
(& "$v\inst2\harnessguard.exe" enable-file-audit "$v\repo\.git") 2>&1 | Select-String '已启用|失败' | ForEach-Object { & $R "[enable] $_" }
$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process "$v\inst2\harnessguard.exe" -ArgumentList "run", "$v\inst2\config.toml" -WorkingDirectory "$v\inst2" `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$v\diagI.out.log" -RedirectStandardError "$v\diagI.err.log"
Start-Sleep 5
& $R "[场景] fake_harness 树内 powershell 长命读 .git\config（8s 存活 > 4663 投递延迟）"
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "powershell -NoProfile -ExecutionPolicy Bypass -File $v\readhold.ps1" 2>&1 | Out-Null
Pop-Location
Start-Sleep 12
$fa = @(Select-String -Path "$v\diagI.out.log" -Pattern 'file-audit] 4663')
& $R ("[4663] 消费行数={0}" -f $fa.Count)
$fa | Select-Object -Last 3 | ForEach-Object { & $R ("[4663] {0}" -f $_.Line.Trim()) }
$vd = @(Select-String -Path "$v\diagI.out.log" -Pattern '\[处置\]|git-dir')
& $R ("[判定/处置行] = {0}" -f $vd.Count)
$vd | Select-Object -First 6 | ForEach-Object { & $R ("[vd] {0}" -f $_.Line.Trim()) }
$fo = @(Select-String -Path "$v\diagI.out.log" -Pattern '\[file\] pid=.*\.git')
& $R ("[file管线] .git FileOpen 行={0}（>0 即过早过滤）" -f $fo.Count)
$fo | Select-Object -First 2 | ForEach-Object { & $R ("[file] {0}" -f $_.Line.Trim()) }

Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 2
(& "$v\inst2\harnessguard.exe" disable-file-audit "$v\repo\.git") 2>&1 | Select-String '已停用|失败' | ForEach-Object { & $R "[disable] $_" }
foreach ($s in @('HarnessGuard','HarnessGuardDns','HarnessGuardSched')) { logman stop $s -ets 2>$null | Out-Null }
& $R ("[终态] ETW 残留={0}；auditpol/SACL 由 disable 还原" -f ((logman query -ets 2>$null | Out-String) -match 'HarnessGuard'))
& $R "== 轮I结束 =="

