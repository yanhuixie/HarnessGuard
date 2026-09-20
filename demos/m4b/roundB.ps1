# M4 第二批复验 轮B（管理员）：一键安装（全新）→ ACL/RSS/probe 补验 → 运行中升级
$ErrorActionPreference = 'Continue'
$v   = "D:\develop\runlefei\HarnessGuard\target\verify-m4b"
$R = { param($m) ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) | Tee-Object -FilePath "$v\roundB.log" -Append }

& $R "== 轮B 开始（一键安装/升级）=="
# 清场：确保无旧服务
$old = sc.exe query HarnessGuard 2>&1 | Out-String
if ($old -notmatch '1060') {
    & $R "[清场] 发现既有服务，先卸载"
    sc.exe stop HarnessGuard | Out-Null; Start-Sleep 3
    & "$v\inst\harnessguard.exe" uninstall 2>&1 | ForEach-Object { & $R "[清场/uninstall] $_" }
    Start-Sleep 2
}

# ---------- 1) 全新安装（计时） ----------
$t0 = Get-Date
$out = (& "$v\inst\harnessguard.exe" install) 2>&1
$elapsed = ((Get-Date) - $t0).TotalSeconds
$out | ForEach-Object { & $R "[install] $_" }
& $R ("[计时] install 全程 {0:N1}s（人工步骤：复制目录 + 1 条命令 + 本轮 UAC）" -f $elapsed)

# ---------- 2) 服务状态 ----------
Start-Sleep 2
& $R ("[sc] query：{0}" -f ((sc.exe query HarnessGuard | Select-String 'STATE') -join ' ').Trim())
& $R ("[sc] qfailure：{0}" -f ((sc.exe qfailure HarnessGuard | Select-String 'RESET_PERIOD|RESTART') -join ' ; ').Trim())
& $R ("[sc] qc binPath：{0}" -f ((sc.exe qc HarnessGuard | Select-String 'BINARY_PATH') -join ' ').Trim())

# ---------- 3) 三件套 + ACL ----------
foreach ($f in @('config.toml','harnessguard.db','web-token.txt','logs')) {
    $p = Join-Path "$v\inst" $f
    & $R ("[文件] {0} 存在={1}" -f $f, (Test-Path $p))
}
$today = Get-Date -Format 'yyyy-MM-dd'
& $R ("[日志] 轮转文件存在={0}" -f (Test-Path "$v\inst\logs\harnessguard.log.$today"))
Get-Content "$v\inst\logs\harnessguard.log.$today" -ErrorAction SilentlyContinue | Select-Object -Last 3 | ForEach-Object { & $R "[日志尾] $_" }
foreach ($f in @('config.toml','harnessguard.db','web-token.txt')) {
    $acl = (icacls "$v\inst\$f") 2>&1 | Out-String
    $ace = ($acl -split "`n" | Where-Object { $_ -match '^\s' }) -join ' | '
    & $R ("[ACL] {0}: {1}" -f $f, $ace.Trim())
}

# ---------- 4) Web API（服务模式） ----------
$token = (Get-Content "$v\inst\web-token.txt" -Raw).Trim()
& $R ("[token] web-token.txt 长度={0}" -f $token.Length)
try {
    $st = Invoke-RestMethod -Headers @{Authorization="Bearer $token"} "http://127.0.0.1:8377/api/status"
    & $R ("[API] /api/status OK：uptime={0}s procs={1} kernel_events={2}" -f $st.uptime_s, $st.procs, $st.source.kernel_events_seen)
} catch { & $R "[API] /api/status 失败：$_" }

# ---------- 5) probe 补验（certutil 长命句柄，第一批同场景对照 1/2） ----------
$before = (Invoke-RestMethod -Headers @{Authorization="Bearer $token"} "http://127.0.0.1:8377/api/status").source
Push-Location "$v\inst"
& "$v\inst\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Start-Sleep 2
& "$v\inst\fake_harness.exe" /c "certutil -hashfile big.bin MD5" 2>&1 | Out-Null
Pop-Location
Start-Sleep 3
$after = (Invoke-RestMethod -Headers @{Authorization="Bearer $token"} "http://127.0.0.1:8377/api/status").source
& $R ("[probe] certutil 两轮：tried {0}→{1} hit {2}→{3}（第一批同场景 hit=1/2）" -f `
    $before.file_probe_tried, $after.file_probe_tried, $before.file_probe_hit, $after.file_probe_hit)

# ---------- 6) RSS 首读 ----------
$proc = Get-Process harnessguard -ErrorAction SilentlyContinue | Select-Object -First 1
if ($proc) {
    $proc.Refresh()
    & $R ("[RSS] 首读（启动约 1 分钟）：WorkingSet={0:N1}MB PrivateMemory={1:N1}MB（预算 ≤100MB）" -f `
        ($proc.WorkingSet64/1MB), ($proc.PrivateMemorySize64/1MB))
}

# ---------- 7) 运行中升级（inst2 → binPath 更新；H-1 修复实测：应跳过端口预检） ----------
& $R "[升级] 旧服务运行中，inst2\harnessguard.exe install（期望：升级模式跳过端口预检）"
$t1 = Get-Date
$up = (& "$v\inst2\harnessguard.exe" install) 2>&1
& $R ("[升级] 耗时 {0:N1}s" -f ((Get-Date)-$t1).TotalSeconds)
$up | ForEach-Object { & $R "[upgrade] $_" }
Start-Sleep 2
& $R ("[升级] binPath 现指向：{0}" -f ((sc.exe qc HarnessGuard | Select-String 'BINARY_PATH') -join ' ').Trim())
& $R ("[升级] 旧目录文件保留：config={0} db={1} logs={2}（保留为设计语义：CWD 锚定新 exe 目录）" -f `
    (Test-Path "$v\inst\config.toml"), (Test-Path "$v\inst\harnessguard.db"), (Test-Path "$v\inst\logs"))
$proc2 = Get-Process harnessguard -ErrorAction SilentlyContinue | Select-Object -First 1
if ($proc2) { & $R ("[升级] 新实例 pid={0}（旧 pid={1}，应为不同 pid）" -f $proc2.Id, $proc.Id) }
$token2 = (Get-Content "$v\inst2\web-token.txt" -Raw -ErrorAction SilentlyContinue).Trim()
try {
    $st2 = Invoke-RestMethod -Headers @{Authorization="Bearer $token2"} "http://127.0.0.1:8377/api/status"
    & $R ("[升级] /api/status OK（新实例 uptime={0}s）" -f $st2.uptime_s)
} catch { & $R "[升级] API 失败：$_" }
& $R "== 轮B结束 =="

