#!/bin/sh
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
set -e
# Solo se systemd e' l'init (non in container/chroot): niente errori spuri.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
