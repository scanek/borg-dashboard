"""
BorgBackup Analytics Dashboard
A lightweight, fast, and modern web interface for monitoring BorgBackup repositories.
"""

import os
import re
import json
import time
import shutil
import uuid
import asyncio
import subprocess
import threading
import hashlib
import secrets
import base64
from collections import deque
from urllib.parse import quote
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, BackgroundTasks, Request, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(
    title="BorgBackup Analytics Dashboard",
    description="Lightweight Web UI & Analytics for BorgBackup repositories",
    version="2.0.0"
)

# Security & Shell Hook Policy
BORG_AUTH_USER = os.getenv("BORG_AUTH_USER", "").strip()
BORG_AUTH_PASSWORD = os.getenv("BORG_AUTH_PASSWORD", "").strip()
BORG_ALLOW_SHELL_HOOKS = os.getenv("BORG_ALLOW_SHELL_HOOKS", "false").lower() in ("true", "1", "yes")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Always allow health check without authentication
    if request.url.path == "/api/health":
        return await call_next(request)

    if BORG_AUTH_USER and BORG_AUTH_PASSWORD:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return Response(
                status_code=401,
                content="Требуется авторизация",
                headers={"WWW-Authenticate": 'Basic realm="BorgBackup Dashboard"'}
            )
        try:
            encoded = auth_header.split(" ", 1)[1]
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
            user_ok = secrets.compare_digest(username, BORG_AUTH_USER)
            pass_ok = secrets.compare_digest(password, BORG_AUTH_PASSWORD)
            if not (user_ok and pass_ok):
                return Response(
                    status_code=401,
                    content="Неверный логин или пароль",
                    headers={"WWW-Authenticate": 'Basic realm="BorgBackup Dashboard"'}
                )
        except Exception:
            return Response(
                status_code=401,
                content="Неверный формат авторизации",
                headers={"WWW-Authenticate": 'Basic realm="BorgBackup Dashboard"'}
            )
    return await call_next(request)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DOCS_DIR = BASE_DIR / "docs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_CACHE_FILE = DATA_DIR / "archive_cache.json"
DR_TEST_FILE = DATA_DIR / "dr_test_result.json"
CONFIG_FILE = BASE_DIR / "config.json"
DATA_CONFIG_FILE = DATA_DIR / "config.json"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

LOGS_DIR = Path(os.getenv("BORG_LOGS_DIR", "/logs" if Path("/logs").exists() else "/volume1/logs"))
RECOVERY_DOC = Path(os.getenv("BORG_GUIDE_PATH", "/app/docs/RECOVERY.md" if Path("/app/docs/RECOVERY.md").exists() else "/volume1/script/ИНСТРУКЦИЯ_ПО_ВОССТАНОВЛЕНИЮ.md"))

# Repository-level locks to prevent simultaneous Borg operations on the same repository
REPO_LOCKS: Dict[str, threading.Lock] = {}
REPO_LOCKS_MUTEX = threading.Lock()

def get_repo_lock(repo_id: str) -> threading.Lock:
    """Retrieve or create a thread lock for a given repository."""
    with REPO_LOCKS_MUTEX:
        if repo_id not in REPO_LOCKS:
            REPO_LOCKS[repo_id] = threading.Lock()
        return REPO_LOCKS[repo_id]

def atomic_save_json(filepath: Path, data: Any):
    """Atomically write JSON data using a temporary file to avoid corruption on power failure."""
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        temp_file = filepath.with_suffix(f".tmp_{os.getpid()}_{uuid.uuid4().hex[:6]}")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_file, filepath)
    except Exception as e:
        print(f"[ERROR] Не удалось атомарно сохранить {filepath}: {e}")

def format_bytes(b: int) -> str:
    if not b or b <= 0:
        return "0 Б"
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    i = 0
    val = float(b)
    while val >= 1024.0 and i < len(units) - 1:
        val /= 1024.0
        i += 1
    return f"{val:.2f} {units[i]}"

def load_dr_test_result() -> Dict[str, Any]:
    if not DR_TEST_FILE.exists():
        return {
            "status": "UNKNOWN",
            "timestamp": None,
            "details": "Тест ещё не проводился"
        }
    try:
        with open(DR_TEST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            tested_at = data.get("tested_at", "")
            time_str = tested_at.replace("T", " ")[:16] if tested_at else "--"
            archive_name = data.get("archive_name", "")
            speed = data.get("speed_mb_s", 0)
            status = data.get("status", "UNKNOWN")
            
            if status == "SUCCESS":
                details = f"{archive_name} ({speed} МБ/с, 100% валиден)"
            else:
                details = f"Ошибка: {data.get('error', 'Не удалось распаковать')[:40]}"

            return {
                "status": status,
                "timestamp": time_str,
                "details": details,
                "data": data
            }
    except Exception as e:
        return {
            "status": "ERROR",
            "timestamp": None,
            "details": str(e)
        }

def save_dr_test_result(res: Dict[str, Any]):
    atomic_save_json(DR_TEST_FILE, res)

def load_repositories_config() -> List[Dict[str, Any]]:
    """Load repositories configuration from config file, env var, or defaults."""
    # 1. Check custom config in data/ or app root
    for cfg_path in [DATA_CONFIG_FILE, CONFIG_FILE]:
        if cfg_path.exists():
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list) and len(data) > 0:
                        return data
                    elif isinstance(data, dict) and "repositories" in data:
                        return data["repositories"]
            except Exception as e:
                print(f"Error loading {cfg_path}: {e}")

    # 2. Check JSON string from BORG_REPOS env var
    env_repos = os.getenv("BORG_REPOS")
    if env_repos:
        try:
            return json.loads(env_repos)
        except Exception as e:
            print(f"Error parsing BORG_REPOS env var: {e}")

    # 3. Default fallback setup
    base_host = (os.getenv("BORG_REPOS_HOST_PATH") or "").strip().rstrip("/")
    default_host1 = f"{base_host}/borg_backup" if base_host else "/srv/backups/borg_backup"
    default_host2 = f"{base_host}/backups/immich-borg" if base_host else "/srv/backups/immich-borg"

    repo1_path = os.getenv("BORG_REPO_1_PATH") or "/repos/borg_backup"
    repo1_host = os.getenv("BORG_REPO_1_HOST_PATH") or default_host1
    
    repo2_path = os.getenv("BORG_REPO_2_PATH") or "/repos/backups/immich-borg"
    repo2_host = os.getenv("BORG_REPO_2_HOST_PATH") or default_host2

    return [
        {
            "id": "docker",
            "name": os.getenv("BORG_REPO_1_NAME", "Docker & Контейнеры"),
            "path": repo1_path,
            "host_path": repo1_host,
            "source": os.getenv("BORG_REPO_1_SOURCE", "/volume1/docker"),
            "schedule": os.getenv("BORG_REPO_1_SCHEDULE", "Ежедневно в 01:00"),
            "description": "Контейнеры, базы данных, пре-дампы и конфигурации"
        },
        {
            "id": "immich",
            "name": os.getenv("BORG_REPO_2_NAME", "Immich Фото & База"),
            "path": repo2_path,
            "host_path": repo2_host,
            "source": os.getenv("BORG_REPO_2_SOURCE", "/volume1/immich"),
            "schedule": os.getenv("BORG_REPO_2_SCHEDULE", "Ежедневно в 00:30"),
            "description": "Медиатека фотографий, видео и база PostgreSQL Immich"
        }
    ]

def get_repo_config(repo_id: str) -> Optional[Dict[str, Any]]:
    """Find repository configuration by ID."""
    repos = load_repositories_config()
    for r in repos:
        if r.get("id") == repo_id:
            return r
    return None

# Global in-memory cache
GLOBAL_CACHE = {
    "last_updated": 0,
    "is_updating": False,
    "data": None
}
CACHE_LOCK = threading.Lock()

# Action tasks for live terminal execution
ACTION_TASKS: Dict[str, Dict[str, Any]] = {}
ACTION_LOCK = threading.Lock()

def get_borg_env() -> dict:
    """Build environment variables for safe Borg invocation."""
    env = os.environ.copy()
    env["BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK"] = "yes"
    env["BORG_RELOCATED_REPO_ACCESS_IS_OK"] = "yes"
    env["BORG_CACHE_DIR"] = os.getenv("BORG_CACHE_DIR", "/tmp/borg_cache")
    return env

def load_archive_cache() -> dict:
    """Load persistent archive metadata cache."""
    if ARCHIVE_CACHE_FILE.exists():
        try:
            with open(ARCHIVE_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_archive_cache(cache: dict):
    """Save persistent archive metadata cache to avoid re-fetching immutable archives."""
    atomic_save_json(ARCHIVE_CACHE_FILE, cache)

def run_borg_command(args: List[str]) -> Any:
    """Execute a Borg CLI command and return parsed JSON."""
    env = get_borg_env()
    try:
        res = subprocess.run(args, capture_output=True, text=True, env=env, timeout=120)
        if res.returncode != 0:
            print(f"Borg command warning: {' '.join(args)}\nStderr: {res.stderr}")
            return None
        return json.loads(res.stdout)
    except Exception as e:
        print(f"Exception running borg {' '.join(args)}: {e}")
        return None

def parse_log_health() -> Dict[str, Any]:
    """Parse backup log files for health indicators."""
    health = {
        "integrity_check": {"status": "UNKNOWN", "timestamp": None, "details": "Лог не найден"},
        "cloud_sync": {"status": "UNKNOWN", "timestamp": None, "details": "Лог не найден"},
        "pre_backup": {"status": "UNKNOWN", "timestamp": None, "details": "Лог не найден"},
        "rsync_cold": {"status": "UNKNOWN", "timestamp": None, "details": "Лог не найден"}
    }

    # 1. Integrity check log
    check_log = LOGS_DIR / "check_borg.log"
    if check_log.exists():
        try:
            lines = check_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-40:]
            for line in reversed(lines):
                m_success = re.search(r"\[(.*?)\]\s+\[SUCCESS\].*?(Все репозитории.*|Ошибок не обнаружено.*)", line)
                if m_success:
                    health["integrity_check"] = {
                        "status": "SUCCESS",
                        "timestamp": m_success.group(1),
                        "details": "Все репозитории проверены, ошибок нет (borg check)"
                    }
                    break
                m_err = re.search(r"\[(.*?)\]\s+\[ERROR\].*?(.*)", line)
                if m_err:
                    health["integrity_check"] = {
                        "status": "ERROR",
                        "timestamp": m_err.group(1),
                        "details": m_err.group(2)
                    }
                    break
        except Exception as e:
            health["integrity_check"]["details"] = str(e)

    # 2. Cloud sync log
    sync_log = LOGS_DIR / "sync_borg_yandex.log"
    if sync_log.exists():
        try:
            lines = sync_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-40:]
            for line in reversed(lines):
                m_success = re.search(r"\[(.*?)\]\s+\[SUCCESS\].*?(Все репозитории Borg успешно выгружены.*)", line)
                if m_success:
                    health["cloud_sync"] = {
                        "status": "SUCCESS",
                        "timestamp": m_success.group(1),
                        "details": "Выгрузка в облачное хранилище успешно завершена"
                    }
                    break
                m_err = re.search(r"\[(.*?)\]\s+\[ERROR\].*?(.*)", line)
                if m_err:
                    health["cloud_sync"] = {
                        "status": "ERROR",
                        "timestamp": m_err.group(1),
                        "details": m_err.group(2)
                    }
                    break
        except Exception as e:
            health["cloud_sync"]["details"] = str(e)

    # 3. Pre backup databases log
    pre_log = LOGS_DIR / "pre_backup_databases.log"
    if pre_log.exists():
        try:
            lines = pre_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-40:]
            for line in reversed(lines):
                m_success = re.search(r"\[(.*?)\]\s+\[SUCCESS\].*?(Все базы данных и тома успешно подготовлены.*)", line)
                if m_success:
                    health["pre_backup"] = {
                        "status": "SUCCESS",
                        "timestamp": m_success.group(1),
                        "details": "Дампы баз данных и тома успешно подготовлены"
                    }
                    break
                m_err = re.search(r"\[(.*?)\]\s+\[ERROR\].*?(.*)", line)
                if m_err:
                    health["pre_backup"] = {
                        "status": "ERROR",
                        "timestamp": m_err.group(1),
                        "details": m_err.group(2)
                    }
                    break
        except Exception as e:
            health["pre_backup"]["details"] = str(e)

    # 4. Rsync cold backup log
    rsync_log = LOGS_DIR / "rsync_backup.log"
    if rsync_log.exists():
        try:
            lines = rsync_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-40:]
            for line in reversed(lines):
                m_success = re.search(r"\[(.*?)\]\s+\[SUCCESS\].*?Резервное копирование Docker успешно завершено.*Сохранено:\s*(.*)", line)
                if m_success:
                    folder = Path(m_success.group(2).strip()).name
                    health["rsync_cold"] = {
                        "status": "SUCCESS",
                        "timestamp": m_success.group(1),
                        "details": f"Снимок на резервный диск сохранен ({folder}), ротация 2 копии"
                    }
                    break
                m_err = re.search(r"\[(.*?)\]\s+\[ERROR\].*?(.*)", line)
                if m_err:
                    health["rsync_cold"] = {
                        "status": "ERROR",
                        "timestamp": m_err.group(1),
                        "details": m_err.group(2)
                    }
                    break
        except Exception as e:
            health["rsync_cold"]["details"] = str(e)

    # 5. DR Restore Test status
    health["dr_test"] = load_dr_test_result()

    return health

def calculate_storage_forecast(repos: List[Dict[str, Any]], archives: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate storage consumption runway and capacity forecast."""
    repo_mount_path = Path("/repos")
    target_path = repo_mount_path if repo_mount_path.exists() else Path(repos[0]["path"] if repos else ".")

    try:
        usage = shutil.disk_usage(str(target_path))
        total_bytes = usage.total
        used_bytes = usage.used
        free_bytes = usage.free
    except Exception:
        total_bytes = 1000 * (1024**3)
        used_bytes = sum(r.get("unique_csize", 0) for r in repos)
        free_bytes = max(0, total_bytes - used_bytes)

    now = datetime.now()
    cutoff_30d = now.timestamp() - (30 * 86400)

    recent_added_bytes = 0
    recent_count = 0
    earliest_time = None
    latest_time = None

    for a in archives:
        start_str = a.get("start", "")
        if start_str:
            try:
                dt = datetime.fromisoformat(start_str.split(".")[0])
                ts = dt.timestamp()
                if earliest_time is None or ts < earliest_time:
                    earliest_time = ts
                if latest_time is None or ts > latest_time:
                    latest_time = ts
                if ts >= cutoff_30d:
                    recent_added_bytes += a.get("deduplicated_size", 0)
                    recent_count += 1
            except Exception:
                pass

    if recent_count > 0 and latest_time:
        span_days = max(1.0, (latest_time - max(cutoff_30d, earliest_time or cutoff_30d)) / 86400.0)
        daily_growth_bytes = recent_added_bytes / max(1.0, span_days)
    elif earliest_time and latest_time and latest_time > earliest_time:
        total_span_days = max(1.0, (latest_time - earliest_time) / 86400.0)
        total_added = sum(a.get("deduplicated_size", 0) for a in archives)
        daily_growth_bytes = total_added / total_span_days
    else:
        daily_growth_bytes = max(100 * 1024 * 1024, sum(r.get("unique_csize", 0) for r in repos) / 90.0)

    monthly_growth_bytes = daily_growth_bytes * 30.4

    if daily_growth_bytes > 0:
        days_until_full = int(free_bytes / daily_growth_bytes)
        months_until_full = round(days_until_full / 30.4, 1)
        years_until_full = round(days_until_full / 365.25, 1)
        try:
            full_dt = now + timedelta(days=days_until_full)
            estimated_full_date = full_dt.strftime("%Y-%m-%d")
        except OverflowError:
            estimated_full_date = "> 10 лет"
    else:
        days_until_full = 99999
        months_until_full = 999
        years_until_full = 99
        estimated_full_date = "Стабильно (без роста)"

    percent_used = round((used_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0
    percent_free = round((free_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0

    return {
        "total_bytes": total_bytes,
        "used_bytes": used_bytes,
        "free_bytes": free_bytes,
        "percent_used": percent_used,
        "percent_free": percent_free,
        "daily_growth_bytes": round(daily_growth_bytes),
        "monthly_growth_bytes": round(monthly_growth_bytes),
        "days_until_full": days_until_full,
        "months_until_full": months_until_full,
        "years_until_full": years_until_full,
        "estimated_full_date": estimated_full_date,
        "health_status": "GOOD" if percent_free > 15 else ("WARNING" if percent_free > 5 else "CRITICAL")
    }

def collect_all_data() -> Dict[str, Any]:
    """Gather metrics, archives, and health status for all configured repositories."""
    archive_cache = load_archive_cache()
    archive_cache_updated = False

    repos_config = load_repositories_config()
    repos_result = []
    all_archives = []

    total_raw_bytes = 0
    total_unique_csize_bytes = 0
    total_archives_count = 0

    for cfg in repos_config:
        repo_path = cfg.get("path")
        host_path = cfg.get("host_path", repo_path)
        repo_id = cfg.get("id")

        if not Path(repo_path).exists():
            print(f"Notice: repo path {repo_path} is currently inaccessible.")
            continue

        # 1. Repo general info
        info_json = run_borg_command(["borg", "info", "--json", repo_path])
        list_json = run_borg_command(["borg", "list", "--json", repo_path])

        if not info_json:
            continue

        cache_stats = info_json.get("cache", {}).get("stats", {})
        total_chunks = cache_stats.get("total_chunks", 0)
        total_unique_chunks = cache_stats.get("total_unique_chunks", 0)
        total_size = cache_stats.get("total_size", 0)
        total_csize = cache_stats.get("total_csize", 0)
        unique_size = cache_stats.get("unique_size", 0)
        unique_csize = cache_stats.get("unique_csize", 0)

        total_raw_bytes += total_size
        total_unique_csize_bytes += unique_csize

        repo_last_modified = info_json.get("repository", {}).get("last_modified")

        archives_raw = list_json.get("archives", []) if list_json else []
        total_archives_count += len(archives_raw)

        # Process archives
        repo_archives = []
        for arch in archives_raw:
            arch_id = arch.get("id")
            arch_name = arch.get("name")
            arch_time = arch.get("start", arch.get("time"))

            # Check cache
            cached_item = archive_cache.get(arch_id)
            if not cached_item:
                arch_info_json = run_borg_command(["borg", "info", "--json", f"{repo_path}::{arch_name}"])
                if arch_info_json and "archives" in arch_info_json and len(arch_info_json["archives"]) > 0:
                    a_data = arch_info_json["archives"][0]
                    stats = a_data.get("stats", {})
                    cached_item = {
                        "id": arch_id,
                        "name": arch_name,
                        "start": a_data.get("start", arch_time),
                        "end": a_data.get("end"),
                        "duration": round(a_data.get("duration", 0), 1),
                        "nfiles": stats.get("nfiles", 0),
                        "original_size": stats.get("original_size", 0),
                        "compressed_size": stats.get("compressed_size", 0),
                        "deduplicated_size": stats.get("deduplicated_size", 0),
                        "hostname": a_data.get("hostname", "")
                    }
                    archive_cache[arch_id] = cached_item
                    archive_cache_updated = True

            if cached_item:
                item_copy = dict(cached_item)
                item_copy["repo_id"] = repo_id
                item_copy["repo_name"] = cfg.get("name", repo_id)
                item_copy["host_path"] = host_path
                repo_archives.append(item_copy)
                all_archives.append(item_copy)

        # Deduplication ratio
        dedup_ratio = round(total_size / unique_csize, 2) if unique_csize > 0 else 1.0
        chunk_dedup_ratio = round((1 - (total_unique_chunks / total_chunks)) * 100, 1) if total_chunks > 0 else 0

        repos_result.append({
            "id": repo_id,
            "name": cfg.get("name", repo_id),
            "source": cfg.get("source", ""),
            "schedule": cfg.get("schedule", ""),
            "description": cfg.get("description", ""),
            "host_path": host_path,
            "last_modified": repo_last_modified,
            "total_size": total_size,
            "total_csize": total_csize,
            "unique_size": unique_size,
            "unique_csize": unique_csize,
            "total_chunks": total_chunks,
            "total_unique_chunks": total_unique_chunks,
            "dedup_ratio": dedup_ratio,
            "chunk_dedup_ratio": chunk_dedup_ratio,
            "archives_count": len(archives_raw),
            "latest_archive": repo_archives[-1] if repo_archives else None
        })

    if archive_cache_updated:
        save_archive_cache(archive_cache)

    # Sort all archives descending by date
    all_archives.sort(key=lambda x: x.get("start", ""), reverse=True)

    # Health from logs
    health = parse_log_health()

    overall_dedup_ratio = round(total_raw_bytes / total_unique_csize_bytes, 2) if total_unique_csize_bytes > 0 else 1.0
    saved_bytes = max(0, total_raw_bytes - total_unique_csize_bytes)

    return {
        "summary": {
            "total_raw_bytes": total_raw_bytes,
            "total_unique_csize_bytes": total_unique_csize_bytes,
            "saved_bytes": saved_bytes,
            "overall_dedup_ratio": overall_dedup_ratio,
            "total_archives": total_archives_count,
            "total_repos": len(repos_result),
            "last_collected": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "repos": repos_result,
        "archives": all_archives,
        "health": health,
        "storage_forecast": calculate_storage_forecast(repos_result, all_archives)
    }

def refresh_data_task():
    """Background task to refresh and update data cache."""
    global GLOBAL_CACHE
    with CACHE_LOCK:
        if GLOBAL_CACHE["is_updating"]:
            return
        GLOBAL_CACHE["is_updating"] = True

    try:
        data = collect_all_data()
        with CACHE_LOCK:
            GLOBAL_CACHE["data"] = data
            GLOBAL_CACHE["last_updated"] = time.time()
    finally:
        with CACHE_LOCK:
            GLOBAL_CACHE["is_updating"] = False

@app.on_event("startup")
def startup_event():
    threading.Thread(target=refresh_data_task, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/status")
async def get_status():
    global GLOBAL_CACHE
    now = time.time()
    if GLOBAL_CACHE["data"] is None or (now - GLOBAL_CACHE["last_updated"] > 300 and not GLOBAL_CACHE["is_updating"]):
        threading.Thread(target=refresh_data_task, daemon=True).start()
        if GLOBAL_CACHE["data"] is None:
            return await asyncio.to_thread(collect_all_data)

    if GLOBAL_CACHE["data"] is not None:
        return GLOBAL_CACHE["data"]
    return await asyncio.to_thread(collect_all_data)

@app.post("/api/refresh")
async def trigger_refresh(background_tasks: BackgroundTasks):
    background_tasks.add_task(refresh_data_task)
    return {"status": "refreshing", "message": "Сбор актуальных данных запущен"}

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "time": datetime.now().isoformat()}

@app.get("/api/guide")
async def get_recovery_guide():
    if RECOVERY_DOC.exists():
        content = RECOVERY_DOC.read_text(encoding="utf-8", errors="ignore")
        return {"title": "Инструкция по восстановлению", "content": content}
    return {"title": "Инструкция не найдена", "content": "Файл руководства не обнаружен по пути " + str(RECOVERY_DOC)}


# -----------------------------------------------------------------------------
# 📂 FILE EXPLORER & DOWNLOAD API
# -----------------------------------------------------------------------------

@app.get("/api/archive/files")
async def get_archive_files(repo_id: str, archive_name: str, folder: Optional[str] = ""):
    """List files and directories inside a specific archive."""
    repo_cfg = get_repo_config(repo_id)
    if not repo_cfg:
        raise HTTPException(status_code=404, detail="Репозиторий не найден")

    repo_path = repo_cfg["path"]
    target = f"{repo_path}::{archive_name}"

    cmd = ["borg", "list", "--json-lines", "--", target]
    if folder:
        cmd.append(folder)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=get_borg_env()
        )
        files = []
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                files.append({
                    "path": item.get("path"),
                    "type": item.get("type", "-"),
                    "mode": item.get("mode", ""),
                    "size": item.get("size", 0),
                    "mtime": item.get("mtime", ""),
                    "healthy": item.get("healthy", True)
                })
            except Exception:
                continue
        proc.wait(timeout=60)
        return {
            "archive_name": archive_name,
            "repo_id": repo_id,
            "repo_name": repo_cfg.get("name", repo_id),
            "folder": folder,
            "total_files": len(files),
            "files": files[:3000]  # Return first 3000 items for responsive UI
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения файлов архива: {e}")


@app.get("/api/archive/download")
async def download_archive_file(repo_id: str, archive_name: str, path: Optional[str] = None, file_path: Optional[str] = None):
    """Stream extract a single file directly to user browser."""
    target_path = path or file_path
    if not target_path:
        raise HTTPException(status_code=400, detail="Не указан путь к файлу")

    repo_cfg = get_repo_config(repo_id)
    if not repo_cfg:
        raise HTTPException(status_code=404, detail="Репозиторий не найден")

    repo_path = repo_cfg["path"]
    raw_filename = Path(target_path).name or "download"
    clean_filename = re.sub(r'[\r\n"\\/]', '_', raw_filename)
    ascii_filename = clean_filename.encode("ascii", "ignore").decode("ascii") or "download"
    encoded_filename = quote(clean_filename)

    cmd = ["borg", "extract", "--stdout", "--", f"{repo_path}::{archive_name}", target_path]

    def iter_file():
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=get_borg_env())
        try:
            while True:
                chunk = proc.stdout.read(64 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            proc.stdout.close()
            proc.wait()

    return StreamingResponse(
        iter_file(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{encoded_filename}'
        }
    )


# -----------------------------------------------------------------------------
# 🔍 ARCHIVE DIFF API
# -----------------------------------------------------------------------------

@app.get("/api/archive/diff")
async def get_archive_diff(repo_id: str, archive1: str, archive2: str):
    """Compare two archives and return itemized changes and summary."""
    repo_cfg = get_repo_config(repo_id)
    if not repo_cfg:
        raise HTTPException(status_code=404, detail="Репозиторий не найден")

    repo_path = repo_cfg["path"]
    cmd = ["borg", "diff", "--json-lines", "--", f"{repo_path}::{archive1}", archive2]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=get_borg_env()
        )
        diff_items = []
        added_count = 0
        removed_count = 0
        modified_count = 0
        net_bytes = 0

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                filepath = data.get("path", "")
                changes = data.get("changes", [])

                primary_type = "modified"
                size_delta = 0
                for ch in changes:
                    ch_type = ch.get("type")
                    if ch_type in ("added", "deleted"):
                        primary_type = "added" if ch_type == "added" else "removed"
                    if "added" in ch and "removed" in ch:
                        delta = ch["added"] - ch["removed"]
                        size_delta += delta
                        net_bytes += delta

                if primary_type == "added":
                    added_count += 1
                elif primary_type == "removed":
                    removed_count += 1
                else:
                    modified_count += 1

                diff_items.append({
                    "path": filepath,
                    "type": primary_type,
                    "delta": size_delta,
                    "changes": changes
                })
            except Exception:
                continue

        proc.wait(timeout=60)
        return {
            "repo_id": repo_id,
            "repo_name": repo_cfg.get("name", repo_id),
            "archive1": archive1,
            "archive2": archive2,
            "summary": {
                "total_changes": len(diff_items),
                "added_files": added_count,
                "removed_files": removed_count,
                "modified_files": modified_count,
                "net_bytes": net_bytes
            },
            "diff": diff_items[:1500]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сравнения архивов: {e}")


# -----------------------------------------------------------------------------
# ⚡ ACTIONS RUNNER WITH LIVE SSE TERMINAL OUTPUT
# -----------------------------------------------------------------------------

class ActionRequest(BaseModel):
    action: str
    repo_id: Optional[str] = None
    archive_name: Optional[str] = None

def run_action_worker(task_id: str, cmd: List[str], env: dict, repo_lock: Optional[threading.Lock] = None):
    task = ACTION_TASKS.get(task_id)
    if not task:
        if repo_lock and repo_lock.locked():
            repo_lock.release()
        return
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            bufsize=1
        )
        task["process"] = proc
        for line in proc.stdout:
            with task["lock"]:
                task["lines"].append(line.rstrip("\r\n"))
        proc.wait()
        with task["lock"]:
            task["exit_code"] = proc.returncode
            task["status"] = "completed" if proc.returncode == 0 else "failed"
            task["completed_at"] = time.time()
    except Exception as e:
        with task["lock"]:
            task["lines"].append(f"Ошибка выполнения: {e}")
            task["status"] = "failed"
            task["exit_code"] = -1
            task["completed_at"] = time.time()
    finally:
        if repo_lock and repo_lock.locked():
            repo_lock.release()

def run_dr_test_worker(task_id: str, repo_id: str, archive_name: Optional[str], env: dict, repo_lock: Optional[threading.Lock] = None):
    global GLOBAL_CACHE
    task = ACTION_TASKS.get(task_id)
    if not task:
        if repo_lock and repo_lock.locked():
            repo_lock.release()
        return

    start_time = time.time()
    temp_dir = Path(f"/tmp/borg_dr_{task_id}")

    try:
        repo_cfg = get_repo_config(repo_id)
        if not repo_cfg:
            raise ValueError(f"Репозиторий {repo_id} не найден")
        repo_path = repo_cfg["path"]

        # 1. Determine archive
        if not archive_name:
            archives = [a for a in (GLOBAL_CACHE.get("data", {}).get("archives") or []) if a.get("repo_id") == repo_id]
            if not archives:
                list_data = run_borg_command(["borg", "list", "--json", repo_path])
                archives = list_data.get("archives", []) if list_data else []
            if not archives:
                raise ValueError("В репозитории нет доступных срезов для проверки")
            archives.sort(key=lambda a: a.get("start", a.get("time", "")), reverse=True)
            
            # Prefer regular scheduled backups over test/temporary ones
            reg_archives = [a for a in archives if not any(t in a.get("name", "").lower() for t in ["test", "dry_run", "tmp", "demo"])]
            if reg_archives:
                archive_name = reg_archives[0]["name"]
            else:
                archive_name = archives[0]["name"]

        target_archive = f"{repo_path}::{archive_name}"

        with task["lock"]:
            task["lines"].append(f"\n=======================================================")
            task["lines"].append(f"🧪 [DR TEST] Симуляция аварийного восстановления")
            task["lines"].append(f"Репозиторий: {repo_cfg.get('name', repo_id)} ({repo_path})")
            task["lines"].append(f"Целевой срез: {archive_name}")
            task["lines"].append(f"Старт: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            task["lines"].append(f"=======================================================\n")

        # Step 1: borg info
        with task["lock"]:
            task["lines"].append(f"[Шаг 1/4] Проверка метаданных и структуры архива...")
            task["lines"].append(f"$ borg info --json {target_archive}")

        cmd_info = ["borg", "info", "--json", target_archive]
        proc_info = subprocess.run(cmd_info, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore", env=env)
        if proc_info.returncode != 0:
            raise RuntimeError(f"Срез недоступен или повреждён: {proc_info.stderr.strip()}")

        info_json = json.loads(proc_info.stdout)
        arch_stats = info_json.get("archives", [{}])[0].get("stats", {})
        original_size = arch_stats.get("original_size", 0)
        nfiles = arch_stats.get("nfiles", 0)

        with task["lock"]:
            task["lines"].append(f"  ✓ Срез доступен: файлов: {nfiles:,}, исходный объем: {format_bytes(original_size)}")

        # Step 2: Sample file selection
        with task["lock"]:
            task["lines"].append(f"\n[Шаг 2/4] Выборка контрольного файла из архива...")
            task["lines"].append(f"$ borg list {target_archive}")

        cmd_list = ["borg", "list", target_archive]
        proc_list = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore", env=env)

        sample_file = None
        for line in proc_list.stdout.splitlines():
            parts = line.strip().split(maxsplit=7)
            if len(parts) >= 8 and parts[0].startswith("-"):
                filepath = parts[7]
                size_str = parts[3]
                try:
                    size_int = int(size_str)
                    if 100 <= size_int <= 10 * 1024 * 1024:
                        if any(filepath.endswith(ext) for ext in [".yml", ".yaml", ".json", ".conf", ".cfg", ".sh", ".txt", ".sql", ".env"]):
                            sample_file = (filepath, size_int)
                            break
                        elif not sample_file:
                            sample_file = (filepath, size_int)
                except ValueError:
                    pass

        if not sample_file:
            for line in proc_list.stdout.splitlines():
                parts = line.strip().split(maxsplit=7)
                if len(parts) >= 8 and parts[0].startswith("-"):
                    sample_file = (parts[7], int(parts[3]) if parts[3].isdigit() else 1024)
                    break

        if not sample_file:
            raise RuntimeError("В архиве не найдено подходящих файлов для распаковки")

        test_filepath, test_expected_size = sample_file
        with task["lock"]:
            task["lines"].append(f"  ✓ Выбран контрольный объект: {test_filepath} ({format_bytes(test_expected_size)})")

        # Step 3: Physical extraction to /tmp/borg_dr_<id>
        temp_dir.mkdir(parents=True, exist_ok=True)
        with task["lock"]:
            task["lines"].append(f"\n[Шаг 3/4] Физическая декомпрессия и распаковка во временную папку...")
            task["lines"].append(f"$ cd {temp_dir} && borg extract -v {target_archive} {test_filepath}")

        t_extract_start = time.time()
        cmd_extract = ["borg", "extract", "-v", target_archive, test_filepath]
        proc_extract = subprocess.Popen(
            cmd_extract,
            cwd=str(temp_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore",
            env=env
        )
        for line in proc_extract.stdout:
            with task["lock"]:
                task["lines"].append(f"  [borg] {line.rstrip()}")
        proc_extract.wait()

        extract_duration = max(0.01, time.time() - t_extract_start)
        if proc_extract.returncode != 0:
            raise RuntimeError(f"Ошибка при извлечении файла (код {proc_extract.returncode})")

        # Locate extracted file
        extracted_full_path = temp_dir / test_filepath
        if not extracted_full_path.exists():
            alt = temp_dir / test_filepath.lstrip("/")
            if alt.exists():
                extracted_full_path = alt
            else:
                matches = list(temp_dir.rglob(Path(test_filepath).name))
                if matches:
                    extracted_full_path = matches[0]
                else:
                    raise RuntimeError(f"Распакованный файл {test_filepath} не найден на диске после extract")

        actual_size = extracted_full_path.stat().st_size
        h = hashlib.sha256()
        with open(extracted_full_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        sha256_hex = h.hexdigest()

        speed_mb_s = (actual_size / (1024 * 1024)) / extract_duration if extract_duration > 0 else 0

        with task["lock"]:
            task["lines"].append(f"  ✓ Файл успешно распакован на диск и проверен!")
            task["lines"].append(f"    - Реальный размер: {actual_size} Б")
            task["lines"].append(f"    - Контрольная сумма SHA-256: {sha256_hex[:24]}...")
            task["lines"].append(f"    - Скорость декомпрессии: ~{speed_mb_s:.1f} МБ/с (время: {extract_duration:.2f} с)")

        # Step 4: Cleanup
        with task["lock"]:
            task["lines"].append(f"\n[Шаг 4/4] Очистка временного каталога...")
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        with task["lock"]:
            task["lines"].append(f"  ✓ Каталог {temp_dir} удалён.")

        total_duration = time.time() - start_time
        with task["lock"]:
            task["lines"].append(f"\n=======================================================")
            task["lines"].append(f"🎉 ИТОГ DR-ТЕСТА: Срез '{archive_name}' 100% ВАЛИДЕН И ВОССТАНОВИМ!")
            task["lines"].append(f"Общее время симуляции: {total_duration:.1f} с")
            task["lines"].append(f"=======================================================")
            task["status"] = "completed"
            task["exit_code"] = 0
            task["completed_at"] = time.time()

        dr_result = {
            "status": "SUCCESS",
            "repo_id": repo_id,
            "archive_name": archive_name,
            "tested_at": datetime.now().isoformat(),
            "duration": round(total_duration, 1),
            "sample_file": test_filepath,
            "file_size": actual_size,
            "sha256": sha256_hex,
            "speed_mb_s": round(speed_mb_s, 1)
        }
        save_dr_test_result(dr_result)

        with CACHE_LOCK:
            if GLOBAL_CACHE.get("data") and "health" in GLOBAL_CACHE["data"]:
                GLOBAL_CACHE["data"]["health"]["dr_test"] = load_dr_test_result()

    except Exception as e:
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        with task["lock"]:
            task["lines"].append(f"\n❌ ОШИБКА DR-ТЕСТА: {e}")
            task["status"] = "failed"
            task["exit_code"] = 1
            task["completed_at"] = time.time()

        dr_result = {
            "status": "ERROR",
            "repo_id": repo_id,
            "archive_name": archive_name or "unknown",
            "tested_at": datetime.now().isoformat(),
            "error": str(e)
        }
        save_dr_test_result(dr_result)

        with CACHE_LOCK:
            if GLOBAL_CACHE.get("data") and "health" in GLOBAL_CACHE["data"]:
                GLOBAL_CACHE["data"]["health"]["dr_test"] = load_dr_test_result()
    finally:
        if repo_lock and repo_lock.locked():
            repo_lock.release()

@app.post("/api/actions/run")
async def run_action(req: ActionRequest):
    """Trigger an interactive action and return task_id for streaming."""
    action = req.action
    repo_cfg = get_repo_config(req.repo_id) if req.repo_id else None

    if action == "refresh_cache":
        threading.Thread(target=refresh_data_task, daemon=True).start()
        return {"status": "ok", "message": "Сбор актуальных данных запущен в фоне"}

    if not repo_cfg:
        raise HTTPException(status_code=400, detail="Не указан или не найден репозиторий")

    repo_lock = get_repo_lock(req.repo_id)
    if not repo_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail=f"Репозиторий '{repo_cfg.get('name', req.repo_id)}' в данный момент выполняет другую операцию. Дождитесь её завершения."
        )

    repo_path = repo_cfg["path"]
    cmd = []
    title = ""

    if action == "break_lock":
        cmd = ["borg", "break-lock", repo_path]
        title = f"Снятие блокировки ({repo_cfg.get('name')})"
    elif action == "check_fast":
        if not req.archive_name:
            repo_lock.release()
            raise HTTPException(status_code=400, detail="Не указано имя архива для быстрой проверки")
        cmd = ["borg", "check", "-v", "--progress", "--archives-only", "-a", req.archive_name, repo_path]
        title = f"Быстрая проверка среза {req.archive_name}"
    elif action == "check_full":
        cmd = ["borg", "check", "-v", "--progress", repo_path]
        title = f"Полная проверка репозитория ({repo_cfg.get('name')})"
    elif action == "dr_test":
        target_name = req.archive_name or "последний срез"
        title = f"DR-тест восстановления: {target_name} ({repo_cfg.get('name')})"
    else:
        repo_lock.release()
        raise HTTPException(status_code=400, detail="Неизвестное действие")

    task_id = str(uuid.uuid4())[:8]
    task_info = {
        "id": task_id,
        "action": action,
        "title": title,
        "command": " ".join(cmd) if cmd else f"DR-тест для {req.archive_name or repo_cfg.get('name')}",
        "status": "running",
        "created_at": time.time(),
        "completed_at": None,
        "exit_code": None,
        "lines": deque([f"$ {' '.join(cmd)}" if cmd else f"$ borg dr-test {repo_path}::{req.archive_name or 'latest'}", f"--- Запуск: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---"], maxlen=2000),
        "lock": threading.Lock()
    }

    with ACTION_LOCK:
        if len(ACTION_TASKS) > 10:
            oldest = min(ACTION_TASKS.keys(), key=lambda k: ACTION_TASKS[k]["created_at"])
            ACTION_TASKS.pop(oldest, None)
        ACTION_TASKS[task_id] = task_info

    if action == "dr_test":
        worker_thread = threading.Thread(
            target=run_dr_test_worker,
            args=(task_id, req.repo_id, req.archive_name, get_borg_env(), repo_lock),
            daemon=True
        )
    else:
        worker_thread = threading.Thread(
            target=run_action_worker,
            args=(task_id, cmd, get_borg_env(), repo_lock),
            daemon=True
        )
    worker_thread.start()

    return {"task_id": task_id, "title": title, "status": "running"}

@app.get("/api/actions/stream/{task_id}")
async def stream_action(task_id: str, request: Request):
    """Server-Sent Events (SSE) stream for terminal output."""
    task = ACTION_TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Задача не найдена")

    async def event_generator():
        sent_index = 0
        while True:
            if await request.is_disconnected():
                break

            with task["lock"]:
                current_lines = list(task["lines"])
                status = task["status"]
                exit_code = task["exit_code"]

            while sent_index < len(current_lines):
                line = current_lines[sent_index]
                sent_index += 1
                data = json.dumps({"line": line, "status": status})
                yield f"data: {data}\n\n"

            if status in ("completed", "failed"):
                end_data = json.dumps({"status": status, "exit_code": exit_code, "done": True})
                yield f"data: {end_data}\n\n"
                break

            await asyncio.sleep(0.3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.get("/api/actions/status/{task_id}")
async def get_action_status(task_id: str):
    task = ACTION_TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    with task["lock"]:
        return {
            "id": task["id"],
            "title": task["title"],
            "status": task["status"],
            "exit_code": task["exit_code"],
            "lines_count": len(task["lines"])
        }


# -----------------------------------------------------------------------------
# 📁 5. SERVER DIRECTORY / FILESYSTEM BROWSER
# -----------------------------------------------------------------------------

@app.get("/api/fs/browse")
async def browse_filesystem(path: Optional[str] = None):
    """Safely browse server directories for selecting backup sources."""
    # Allowed roots whitelist (common server paths + custom via BORG_ALLOWED_ROOTS)
    allowed_roots = [
        Path("/srv"), Path("/volume1"), Path("/repos"), Path("/app/data"),
        Path("/mnt"), Path("/home"), Path("/data"), Path("/var"), Path("/storage")
    ]
    env_roots = os.getenv("BORG_ALLOWED_ROOTS", "")
    if env_roots:
        for r in env_roots.split(","):
            if r.strip():
                allowed_roots.append(Path(r.strip()))

    # Local dev fallback
    if not any(r.exists() for r in allowed_roots):
        allowed_roots.append(BASE_DIR.resolve())

    if not path or not path.strip():
        # Pick the first existing allowed root
        target = next((r.resolve() for r in allowed_roots if r.exists()), BASE_DIR.resolve())
    else:
        try:
            target = Path(path.strip()).resolve()
        except Exception:
            raise HTTPException(status_code=400, detail="Некорректный путь")

        is_allowed = False
        for root in allowed_roots:
            if root.exists():
                try:
                    target.relative_to(root.resolve())
                    is_allowed = True
                    break
                except ValueError:
                    if target == root.resolve():
                        is_allowed = True
                        break

        if not is_allowed:
            raise HTTPException(status_code=403, detail="Доступ к указанной директории запрещён политикой безопасности")

    if not target.exists() or not target.is_dir():
        raise HTTPException(status_code=404, detail="Указанная директория не найдена")

    items = []
    try:
        entries = sorted(target.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        for entry in entries:
            try:
                is_dir = entry.is_dir()
                stat = entry.stat()
                items.append({
                    "name": entry.name,
                    "path": str(entry).replace("\\", "/"),
                    "is_dir": is_dir,
                    "size": stat.st_size if not is_dir else 0,
                    "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "readable": os.access(entry, os.R_OK)
                })
            except (PermissionError, OSError):
                continue
    except PermissionError:
        raise HTTPException(status_code=403, detail="Нет прав для чтения директории")

    # Build breadcrumbs
    breadcrumbs = []
    curr = target
    parts = []
    while curr != curr.parent:
        parts.append({"name": curr.name or "/", "path": str(curr).replace("\\", "/")})
        curr = curr.parent
    if curr.name == "" or curr.name == "/":
        parts.append({"name": "Корень (/)", "path": "/"})
    breadcrumbs = list(reversed(parts))

    parent_path = str(target.parent).replace("\\", "/") if target.parent != target else None

    return {
        "current_path": str(target).replace("\\", "/"),
        "parent_path": parent_path,
        "breadcrumbs": breadcrumbs,
        "items": items[:400]
    }


# -----------------------------------------------------------------------------
# ⚙️ 6. INTERACTIVE BACKUP JOBS CONFIGURATOR & SCHEDULER
# -----------------------------------------------------------------------------

JOBS_FILE = DATA_DIR / "jobs.json"
JOBS_LOCK = threading.Lock()

class BackupJobRetention(BaseModel):
    keep_daily: int = 7
    keep_weekly: int = 4
    keep_monthly: int = 3

class BackupJobSchedule(BaseModel):
    enabled: bool = True
    frequency: str = "daily"  # "daily", "weekly", "manual"
    time: str = "02:00"       # "HH:MM"
    days: List[int] = [1, 2, 3, 4, 5, 6, 7]  # 1=Mon, 7=Sun

class BackupJobModel(BaseModel):
    id: Optional[str] = None
    name: str
    repo_id: str
    archive_prefix: str
    sources: List[str]
    exclude_patterns: List[str] = []
    compression: str = "auto,zstd,6"
    retention: BackupJobRetention = BackupJobRetention()
    schedule: BackupJobSchedule = BackupJobSchedule()
    pre_backup_cmd: Optional[str] = None
    post_backup_cmd: Optional[str] = None

def get_default_jobs() -> List[Dict[str, Any]]:
    return [
        {
            "id": "job-docker-sys",
            "name": "Docker & Контейнеры (Системный OMV)",
            "repo_id": "docker",
            "archive_prefix": "docker_dir",
            "sources": ["/srv/dev-disk-by-uuid-0ec712e9-1748-4fd2-af21-4ccfc9791cd1/docker"],
            "exclude_patterns": ["*.sock", "*.tmp"],
            "compression": "auto,zlib,9",
            "retention": {
                "keep_daily": 7,
                "keep_weekly": 4,
                "keep_monthly": 3
            },
            "schedule": {
                "enabled": True,
                "frequency": "daily",
                "time": "01:00",
                "days": [1, 2, 3, 4, 5, 6, 7]
            },
            "is_system": True,
            "created_at": "2026-09-01T00:00:00",
            "last_run": None
        },
        {
            "id": "job-immich-sys",
            "name": "Immich Фотографии & База Данных",
            "repo_id": "immich",
            "archive_prefix": "immich",
            "sources": ["/volume1/immich"],
            "exclude_patterns": ["/volume1/immich/thumbs", "/volume1/immich/encoded-video"],
            "compression": "zstd,6",
            "retention": {
                "keep_daily": 14,
                "keep_weekly": 4,
                "keep_monthly": 6
            },
            "schedule": {
                "enabled": True,
                "frequency": "daily",
                "time": "00:30",
                "days": [1, 2, 3, 4, 5, 6, 7]
            },
            "is_system": True,
            "created_at": "2026-09-01T00:00:00",
            "last_run": None
        }
    ]

def load_jobs() -> List[Dict[str, Any]]:
    if not JOBS_FILE.exists():
        defaults = get_default_jobs()
        save_jobs(defaults)
        return defaults
    try:
        with open(JOBS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Ошибка чтения jobs.json: {e}")
        return get_default_jobs()

def save_jobs(jobs: List[Dict[str, Any]]):
    atomic_save_json(JOBS_FILE, jobs)

@app.get("/api/jobs")
async def get_jobs():
    """Return all configured backup jobs."""
    with JOBS_LOCK:
        return {"jobs": load_jobs()}

@app.post("/api/jobs")
async def create_job(job: BackupJobModel):
    """Create a new backup job."""
    if not job.sources:
        raise HTTPException(status_code=400, detail="Не указаны источники для резервного копирования")

    new_id = f"job-{str(uuid.uuid4())[:8]}"
    job_dict = job.dict()
    job_dict["id"] = new_id
    job_dict["is_system"] = False
    job_dict["created_at"] = datetime.now().isoformat()
    job_dict["last_run"] = None

    with JOBS_LOCK:
        jobs = load_jobs()
        jobs.append(job_dict)
        save_jobs(jobs)

    return {"status": "ok", "job": job_dict}

@app.put("/api/jobs/{job_id}")
async def update_job(job_id: str, job: BackupJobModel):
    """Update an existing backup job."""
    with JOBS_LOCK:
        jobs = load_jobs()
        idx = next((i for i, j in enumerate(jobs) if j["id"] == job_id), None)
        if idx is None:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        old_job = jobs[idx]
        updated = job.dict()
        updated["id"] = job_id
        updated["is_system"] = old_job.get("is_system", False)
        updated["created_at"] = old_job.get("created_at", datetime.now().isoformat())
        updated["last_run"] = old_job.get("last_run")

        jobs[idx] = updated
        save_jobs(jobs)

    return {"status": "ok", "job": updated}

@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a custom backup job."""
    with JOBS_LOCK:
        jobs = load_jobs()
        target_job = next((j for j in jobs if j["id"] == job_id), None)
        if not target_job:
            raise HTTPException(status_code=404, detail="Задача не найдена")
        if target_job.get("is_system"):
            raise HTTPException(status_code=400, detail="Системную задачу OMV нельзя удалить")

        jobs = [j for j in jobs if j["id"] != job_id]
        save_jobs(jobs)

    return {"status": "ok", "message": "Задача удалена"}

def execute_job_worker(task_id: str, job: Dict[str, Any], repo_lock: Optional[threading.Lock] = None):
    """Execute complete backup workflow: create -> prune -> compact."""
    task = ACTION_TASKS.get(task_id)
    if not task:
        if repo_lock and repo_lock.locked():
            repo_lock.release()
        return

    repo_cfg = get_repo_config(job["repo_id"])
    if not repo_cfg:
        with task["lock"]:
            task["lines"].append(f"[ERROR] Репозиторий {job['repo_id']} не найден!")
            task["status"] = "failed"
            task["exit_code"] = 1
        if repo_lock and repo_lock.locked():
            repo_lock.release()
        return

    repo_path = repo_cfg["path"]
    prefix = job.get("archive_prefix", "backup").strip()
    sources = job.get("sources", [])
    excludes = job.get("exclude_patterns", [])
    compression = job.get("compression", "auto,zstd,6").strip()
    retention = job.get("retention", {})
    archive_name = f"{prefix}-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

    env = get_borg_env()
    start_time = time.time()
    success = True

    try:
        # Step 1: Pre-backup command (if specified)
        pre_cmd = job.get("pre_backup_cmd")
        if pre_cmd and pre_cmd.strip():
            if not BORG_ALLOW_SHELL_HOOKS:
                with task["lock"]:
                    task["lines"].append("⚠️ [SECURITY] pre_backup_cmd пропущена: выполнение шелл-команд отключено политикой безопасности (BORG_ALLOW_SHELL_HOOKS=false).")
            else:
                with task["lock"]:
                    task["lines"].append(f"--- [Шаг 0/3] Предварительная команда: {pre_cmd} ---")
                p = subprocess.Popen(pre_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="ignore")
                for l in p.stdout:
                    with task["lock"]:
                        task["lines"].append(f"[pre] {l.rstrip()}")
                p.wait()

        # Step 2: Borg Create
        cmd_create = [
            "borg", "create",
            "--verbose",
            "--stats",
            "--show-rc",
            "--progress",
            "--compression", compression,
            "--exclude-caches"
        ]
        for exc in excludes:
            if exc.strip():
                cmd_create.extend(["--exclude", exc.strip()])

        cmd_create.append(f"{repo_path}::{archive_name}")
        cmd_create.extend(sources)

        with task["lock"]:
            task["lines"].append(f"--- [Шаг 1/3] Создание снимка: {archive_name} ---")
            task["lines"].append(f"$ {' '.join(cmd_create)}")

        proc_create = subprocess.Popen(
            cmd_create,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            bufsize=1
        )
        task["process"] = proc_create
        for line in proc_create.stdout:
            with task["lock"]:
                task["lines"].append(line.rstrip("\r\n"))
        proc_create.wait()

        if proc_create.returncode != 0:
            success = False
            with task["lock"]:
                task["lines"].append(f"[ERROR] Ошибка при создании снимка Borg (код {proc_create.returncode})")

        # Step 3: Borg Prune (only if create succeeded)
        if success and retention:
            kd = retention.get("keep_daily", 7)
            kw = retention.get("keep_weekly", 4)
            km = retention.get("keep_monthly", 3)
            cmd_prune = [
                "borg", "prune",
                "--list",
                "--show-rc",
                "--glob-archives", f"{prefix}-*",
                f"--keep-daily={kd}",
                f"--keep-weekly={kw}",
                f"--keep-monthly={km}",
                repo_path
            ]
            with task["lock"]:
                task["lines"].append(f"\n--- [Шаг 2/3] Ротация старых копий (keep: daily={kd}, weekly={kw}, monthly={km}) ---")
                task["lines"].append(f"$ {' '.join(cmd_prune)}")

            proc_prune = subprocess.Popen(cmd_prune, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="ignore", env=env)
            for line in proc_prune.stdout:
                with task["lock"]:
                    task["lines"].append(line.rstrip("\r\n"))
            proc_prune.wait()

        # Step 4: Borg Compact (optional, run only if job.get('run_compact', False) is True; large HDD repos take minutes)
        if success and job.get("run_compact", False):
            cmd_compact = ["borg", "compact", "--threshold", "10", repo_path]
            with task["lock"]:
                task["lines"].append(f"\n--- [Шаг 3/3] Оптимизация хранилища (compact --threshold 10) ---")
                task["lines"].append(f"$ {' '.join(cmd_compact)}")

            proc_compact = subprocess.Popen(cmd_compact, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="ignore", env=env)
            for line in proc_compact.stdout:
                with task["lock"]:
                    task["lines"].append(line.rstrip("\r\n"))
            proc_compact.wait()

        # Step 5: Post-backup command (if specified)
        post_cmd = job.get("post_backup_cmd")
        if post_cmd and post_cmd.strip():
            if not BORG_ALLOW_SHELL_HOOKS:
                with task["lock"]:
                    task["lines"].append("⚠️ [SECURITY] post_backup_cmd пропущена: выполнение шелл-команд отключено политикой безопасности (BORG_ALLOW_SHELL_HOOKS=false).")
            else:
                with task["lock"]:
                    task["lines"].append(f"\n--- [Пост-шаг] Команда после бэкапа: {post_cmd} ---")
                p = subprocess.Popen(post_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="ignore")
                for l in p.stdout:
                    with task["lock"]:
                        task["lines"].append(f"[post] {l.rstrip()}")
                p.wait()

        duration = time.time() - start_time
        status_str = "completed" if success else "failed"

        with task["lock"]:
            task["status"] = status_str
            task["exit_code"] = 0 if success else 1
            task["completed_at"] = time.time()
            task["lines"].append(f"\n--- Завершено: {status_str} (время: {int(duration)} сек) ---")

        # Record last run in jobs.json
        with JOBS_LOCK:
            jobs = load_jobs()
            j = next((x for x in jobs if x["id"] == job["id"]), None)
            if j:
                j["last_run"] = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": status_str,
                    "archive_name": archive_name,
                    "duration": int(duration)
                }
                save_jobs(jobs)

        # Trigger dashboard cache refresh in background
        threading.Thread(target=refresh_data_task, daemon=True).start()

    except Exception as e:
        with task["lock"]:
            task["lines"].append(f"\n[CRITICAL ERROR] Исключение при выполнении бэкапа: {e}")
            task["status"] = "failed"
            task["exit_code"] = -1
            task["completed_at"] = time.time()
    finally:
        if repo_lock and repo_lock.locked():
            repo_lock.release()

def start_job_execution(job_id: str) -> str:
    """Register and start an interactive backup job."""
    with JOBS_LOCK:
        jobs = load_jobs()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if not job:
            raise HTTPException(status_code=404, detail="Задача не найдена")

    repo_id = job.get("repo_id")
    repo_lock = get_repo_lock(repo_id)
    if not repo_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail=f"Репозиторий '{repo_id}' в данный момент выполняет другую операцию. Повторите попытку позже."
        )

    task_id = str(uuid.uuid4())[:8]
    title = f"Бэкап: {job['name']}"

    task_info = {
        "id": task_id,
        "action": "backup_job",
        "title": title,
        "command": f"borg backup job {job['name']}",
        "status": "running",
        "created_at": time.time(),
        "completed_at": None,
        "exit_code": None,
        "lines": deque([
            f"=== Запуск задачи резервного копирования: {job['name']} ===",
            f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Репозиторий: {job['repo_id']}",
            f"Источники: {', '.join(job.get('sources', []))}",
            "============================================================"
        ], maxlen=2000),
        "lock": threading.Lock()
    }

    with ACTION_LOCK:
        if len(ACTION_TASKS) > 10:
            oldest = min(ACTION_TASKS.keys(), key=lambda k: ACTION_TASKS[k]["created_at"])
            ACTION_TASKS.pop(oldest, None)
        ACTION_TASKS[task_id] = task_info

    worker = threading.Thread(target=execute_job_worker, args=(task_id, job, repo_lock), daemon=True)
    worker.start()
    return task_id

@app.post("/api/jobs/{job_id}/run")
async def run_backup_job_api(job_id: str):
    """Trigger immediate interactive backup execution."""
    task_id = start_job_execution(job_id)
    return {"status": "running", "task_id": task_id}

# Background Scheduler Thread
def background_scheduler():
    """Background scheduler evaluating jobs every 25 seconds with per-job minute tracking."""
    job_last_run_min: Dict[str, str] = {}
    while True:
        try:
            time.sleep(25)
            now = datetime.now()
            curr_min = now.strftime("%Y-%m-%d %H:%M")
            curr_time = now.strftime("%H:%M")
            curr_dow = now.isoweekday()

            with JOBS_LOCK:
                jobs = load_jobs()

            for job in jobs:
                if job.get("is_system"):
                    continue  # System jobs already managed by OMV cron
                sched = job.get("schedule", {})
                if not sched.get("enabled", False):
                    continue

                freq = sched.get("frequency", "daily")
                target_time = sched.get("time", "")

                if target_time != curr_time:
                    continue

                if freq == "weekly" and curr_dow not in sched.get("days", [1]):
                    continue

                job_id = job.get("id")
                if job_last_run_min.get(job_id) == curr_min:
                    continue

                print(f"[SCHEDULER] Автозапуск задачи: {job.get('name')} ({job_id})")
                job_last_run_min[job_id] = curr_min
                try:
                    start_job_execution(job_id)
                except Exception as e:
                    print(f"[SCHEDULER] Не удалось запустить задачу {job_id}: {e}")

        except Exception as e:
            print(f"[SCHEDULER ERROR] {e}")
            time.sleep(25)

# Start background scheduler daemon
threading.Thread(target=background_scheduler, daemon=True).start()


