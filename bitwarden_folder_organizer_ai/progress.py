from __future__ import annotations

import sys
import time


def progress(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def truncate_name(text: str, limit: int = 60) -> str:
    value = str(text or "")
    if len(value) <= limit:
        return value
    if limit <= 3:
        return value[:limit]
    return value[: limit - 3] + "..."


def format_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    rem = seconds - minutes * 60
    return f"{minutes}m{int(rem):02d}s"


def estimate_eta(start_time: float, done: int, total: int) -> str:
    if done <= 0:
        return "unknown"
    elapsed = time.time() - start_time
    avg = elapsed / done
    remaining = max(0, total - done)
    return format_duration(avg * remaining)


def shorten_id(value: str, length: int = 8) -> str:
    s = str(value or "")
    return s[:length] if s else s
