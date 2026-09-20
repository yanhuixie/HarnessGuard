# M4 第二批复验 轮H（管理员）：4663 最终断点定位（解析已修，看前缀匹配层）+ 还原
$ErrorActionPreference = 'Continue'
$v    = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$root = "D:\develop\runlefei\HarnessGuard"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundH.log" -Append }

& $R "== 轮H 开始 =="
Copy-Item "$root\target\release\harnessguard.exe" "$v\inst2\harnessguard.exe" -Force
Set-Location "$v\inst2"
$en = (& "$v\inst2\harnessguard.exe" enable-file-audit "$v\repo\.git") 2>&1
$en | ForEach-Object { & $R "[enable] $_" }
$pol = (auditpol /get /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' 2>&1 | Out-String)
& $R ("[auditpol] {0}" -f (($pol -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^系统|^类别|^---|^$' }) -join ' ; ').Trim())

$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process "$v\inst2\harnessguard.exe" -ArgumentList "run", "$v\inst2\config.toml" -WorkingDirectory "$v\inst2" `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$v\diagH.out.log" -RedirectStandardError "$v\diagH.err.log"
Start-Sleep 5
$sub = (Select-String -Path "$v\diagH.out.log" -Pattern '订阅已建立').Line
& $R ("[订阅] {0}" -f ($(if ($sub) { "是" } else { "无" })))
Push-Location "$v\inst2"
& "$v\inst2\fake_harness.exe" /c "type $v\repo\.git\config" 2>&1 | Out-Null
Pop-Location
Start-Sleep 5
# 全部 file-audit 行（不过滤）
$lines = Select-String -Path "$v\diagH.out.log" -Pattern 'file-audit'
& $R ("[file-audit 行数={0}]" -f $lines.Count)
$lines | Select-Object -First 8 | ForEach-Object { & $R ("[fa] {0}" -f $_.Line.Trim()) }
# 判定行
$vd = @(Select-String -Path "$v\diagH.out.log" -Pattern 'git-dir|\.git')
& $R ("[git 相关行={0}]" -f $vd.Count)
$vd | Select-Object -First 5 | ForEach-Object { & $R ("[git] {0}" -f $_.Line.Trim()) }

Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$dis = (& "$v\inst2\harnessguard.exe" disable-file-audit "$v\repo\.git") 2>&1
$dis | Select-String '已停用|失败' | ForEach-Object { & $R "[disable] $_" }
foreach ($s in @('HarnessGuard','HarnessGuardDns','HarnessGuardSched')) { logman stop $s -ets 2>$null | Out-Null }
& $R ("[终态] ETW 残留={0}" -f ((logman query -ets 2>$null | Out-String) -match 'HarnessGuard'))
& $R "== 轮H结束 =="

