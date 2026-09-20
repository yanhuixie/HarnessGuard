#!/bin/sh
# HarnessGuard Linux 安装脚本（M2 预写占位——**未编译验证、未实机运行**，
# 平台验证状态见 AGENTS.md：hg-plat-linux 代码从未在真实 Linux 编译）。
# M2 里程碑时按 eBPF/fanotify 实测校准后启用。
#
# 用法（root）：./install.sh [安装目录，默认 /opt/harnessguard]
set -eu

DIR="${1:-/opt/harnessguard}"
SERVICE=harnessguard
BIN="$DIR/harnessguard"

[ "$(id -u)" = 0 ] || { echo "需 root 运行"; exit 1; }
command -v "$BIN" >/dev/null 2>&1 || [ -x "$BIN" ] || { echo "未找到 $BIN（先 cargo build --release 并部署）"; exit 1; }

# 配置生成（缺省落默认）——M2 校准：Linux 侧以相同"首启写默认配置"逻辑
# （run_server 已实现），此处无需预生成，仅确保目录与权限
mkdir -p "$DIR/logs"
chmod 700 "$DIR/logs"

# systemd 单元（对应 Windows 服务的 LocalSystem 自启 + 三级重启）
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=HarnessGuard（AI harness 行为防护）
After=network.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$BIN service
Restart=always
RestartSec=5
# 对应 §8.2 自保护：配置/库仅 root 可写（DACL 由 systemd 的 User=root +
# chmod 实现，Linux 侧无 DACL 概念）
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
# restart 而非 start：对运行中的旧实例即升级语义（换二进制/unit 后重启生效，
# 对未运行服务等价 start）——与 Windows install 的版本化升级路径对齐
systemctl restart "$SERVICE"
systemctl --no-pager --lines 5 status "$SERVICE" || true
echo "Web token：$DIR/web-token.txt（服务启动后生成）"
echo "卸载：./uninstall.sh"
