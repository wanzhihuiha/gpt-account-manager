"""应用版本号与静态资源版本号计算。"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping


def load_app_version(package_file: Path, *, environ: Mapping[str, str] | None = None) -> str:
    """读取后端展示版本号，优先使用环境变量，其次读取 package.json。"""
    source = os.environ if environ is None else environ
    env_version = (source.get("GPT_ACCOUNT_MANAGER_VERSION") or source.get("APP_VERSION") or "").strip()
    if env_version:
        return env_version
    try:
        payload = json.loads(package_file.read_text(encoding="utf-8"))
        version = str(payload.get("version") or "").strip()
        if version:
            return version
    except Exception:
        pass
    return "0.0.0"


def load_asset_version(static_dir: Path, app_version: str) -> str:
    """根据静态资源最后修改时间生成前端缓存版本号。"""
    latest = 0
    try:
        for pattern in ("*.css", "*.js", "*.svg"):
            for item in static_dir.glob(pattern):
                latest = max(latest, int(item.stat().st_mtime))
    except Exception:
        latest = 0
    return f"{app_version}.{latest}" if latest else app_version


__all__ = [
    "load_app_version",
    "load_asset_version",
]
