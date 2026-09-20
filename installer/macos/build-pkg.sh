#!/bin/sh
# HarnessGuard macOS pkg 构建脚本（M3 预写占位——**未编译验证、未实机运行**，
# hg-plat-macos 代码从未在真实 macOS 编译；M3 时按 auditpipe/通知 LaunchAgent
# 桥实测校准后启用）。
#
# 结构（技术设计 §5.3 / M4 里程碑）：
# - /Applications/HarnessGuard/harnessguard        主程序（LaunchDaemon 拉起）
# - /Library/LaunchDaemons/com.harnessguard.plist   特权守护（对应 Windows 服务）
# - 通知代理：per-user LaunchAgent（技术设计 §8.1 会话桥，M3 实现后加入）
#
# 用法（macOS 构建机）：cargo build --release --target aarch64-apple-darwin &&
#                       ./build-pkg.sh && 产物 dist/HarnessGuard-<ver>.pkg
set -eu

VER="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -1)"
STAGE=dist/stage
rm -rf "$STAGE" && mkdir -p "$STAGE/Applications/HarnessGuard" "$STAGE/Library/LaunchDaemons"

cp target/*/release/harnessguard "$STAGE/Applications/HarnessGuard/" 2>/dev/null \
  || cp target/release/harnessguard "$STAGE/Applications/HarnessGuard/"

cat > "$STAGE/Library/LaunchDaemons/com.harnessguard.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.harnessguard</string>
  <key>ProgramArguments</key><array>
    <string>/Applications/HarnessGuard/harnessguard</string><string>service</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>WorkingDirectory</key><string>/Applications/HarnessGuard</string>
</dict></plist>
EOF

pkgbuild --root "$STAGE" --identifier com.harnessguard --version "${VER:-0.1.0}" \
  "dist/HarnessGuard-${VER:-0.1.0}.pkg"
echo "M3 启用前本产物未经验证，仅供结构参考"
