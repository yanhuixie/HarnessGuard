# M4 SSE verdict 帧实证（非提权可跑）：RunKey 判定（注册表轮询，不依赖 ETW）
$ErrorActionPreference = 'Continue'
$root = "D:\develop\runlefei\HarnessGuard"
$demo = Join-Path $root "target\verify-m4\sse-test"
$exe  = Join-Path $root "target\release\harnessguard.exe"
New-Item -ItemType Directory -Force -Path $demo | Out-Null
Copy-Item "D:\develop\runlefei\HarnessGuard\target\verify-m4\config.toml" "$demo\config.toml" -Force

$env:RUST_LOG = 'info'
$svc = Start-Process $exe -ArgumentList "run", "$demo\config.toml" -WorkingDirectory $demo `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$demo\svc.out.log" -RedirectStandardError "$demo\svc.err.log"
Start-Sleep 3
$token = (Select-String -Path "$demo\svc.out.log" -Pattern 'token=([0-9a-f]+)').Matches[0].Groups[1].Value
"[启动] token=$token（非提权：ETW 预期失败，RunKey 轮询正常）"
$H = @{ Authorization = "Bearer $token" }

# 后台采集 SSE（40s 窗口，覆盖 30s RunKey 轮询周期）
$job = Start-Job { param($t, $d) & "$env:SystemRoot\System32\curl.exe" -N -s --max-time 40 `
    -H "Authorization: Bearer $t" -o "$d\sse6.log" "http://127.0.0.1:8377/api/stream" } -ArgumentList $token, $demo
Start-Sleep 2

# 触发判定：写 HKCU RunKey（轮询周期 30s）
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v HgSseTest /d "cmd /c echo sse" /f | Out-Null
"[RunKey] 已写入 HgSseTest，等待轮询（30s 周期）+ SSE 窗口收口…"
Wait-Job $job -Timeout 50 | Out-Null
Remove-Job $job -Force

Start-Sleep 2
$sse = ""
try { $sse = Get-Content "$demo\sse6.log" -Raw -ErrorAction Stop } catch {}
"[SSE] retry帧:{0}  verdict帧:{1}  audit帧:{2}  总字节:{3}" -f `
    ($sse -match 'retry: 3000'), ([regex]::Matches($sse, 'event: verdict').Count), `
    ([regex]::Matches($sse, 'event: audit').Count), $sse.Length
if ($sse -match '(event: verdict\ndata: \{[^\r\n]{0,200})') { "[SSE] verdict 帧样例：$($Matches[1])" }
try {
  $vs = Invoke-RestMethod -Headers $H "http://127.0.0.1:8377/api/verdicts?limit=10"
  "[判定] 共 {0} 条：{1}" -f @($vs).Count, (($vs | ForEach-Object { "$($_.rule_id)/$($_.action)" }) -join ' ')
} catch { "[判定] 查询失败 $_" }

# 清场
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v HgSseTest /f 2>$null | Out-Null
Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
"[结束]"
