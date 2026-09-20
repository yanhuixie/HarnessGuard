#!/bin/sh
# HarnessGuard Linux 卸载脚本（M2 预写占位——**未编译验证、未实机运行**）。
# 数据文件（config.toml / harnessguard.db / logs）保留由用户决定。
set -eu

DIR="${1:-/opt/harnessguard}"
SERVICE=harnessguard

[ "$(id -u)" = 0 ] || { echo "需 root 运行"; exit 1; }

systemctl stop "$SERVICE" 2>/dev/null || true
systemctl disable "$SERVICE" 2>/dev/null || true
rm -f "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
rm -f "$DIR/web-token.txt"
echo "服务已卸载；保留（含审计数据，可手工删除）：$DIR/config.toml $DIR/harnessguard.db $DIR/logs"
