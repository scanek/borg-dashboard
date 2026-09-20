"""
BorgBackup Analytics Dashboard
A lightweight, fast, and modern web interface for monitoring BorgBackup repositories.
"""

import os
import re
import json
import time
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(
    title="BorgBackup Analytics Dashboard",
    description="Lightweight Web UI & Analytics for BorgBackup repositories",
    version="1.0.0"
)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DOCS_DIR = BASE_DIR / "docs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_CACHE_FILE = DATA_DIR / "archive_cache.json"
CONFIG_FILE = BASE_DIR / "config.json"
DATA_CONFIG_FILE = DATA_DIR / "config.json"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

LOGS_DIR = Path(os.getenv("BORG_LOGS_DIR", "/logs" if Path("/logs").exists() else "/volume1/logs"))
RECOVERY_DOC = Path(os.getenv("BORG_GUIDE_PATH", "/app/docs/RECOVERY.md" if Path("/app/docs/RECOVERY.md").exists() else "/volume1/script/ИНСТРУКЦИЯ_ПО_ВОССТАНОВЛЕНИЮ.md"))

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

# Global in-memory cache
GLOBAL_CACHE = {
    "last_updated": 0,
    "is_updating": False,
    "data": None
}
CACHE_LOCK = threading.Lock()

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
    try:
        with open(ARCHIVE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Error saving archive cache: {e}")

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

    return health

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
        "health": health
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
            return collect_all_data()

    return GLOBAL_CACHE["data"] or collect_all_data()

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
