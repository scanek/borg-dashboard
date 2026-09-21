import os
import sys
import unittest
import tempfile
import json
from pathlib import Path

# Add app directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from main import format_bytes, RepoLock, atomic_save_json, calculate_storage_forecast

class TestBorgDashboard(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0 Б")
        self.assertEqual(format_bytes(-50), "0 Б")
        self.assertEqual(format_bytes(1024), "1.00 КБ")
        self.assertEqual(format_bytes(1048576), "1.00 МБ")
        self.assertEqual(format_bytes(1073741824), "1.00 ГБ")
        self.assertEqual(format_bytes(1099511627776), "1.00 ТБ")

    def test_repo_lock_ownership(self):
        lock = RepoLock("test_repo")
        self.assertFalse(lock.is_locked())
        self.assertIsNone(lock.get_owner())

        # Task 1 acquires lock
        self.assertTrue(lock.acquire("task_1"))
        self.assertTrue(lock.is_locked())
        self.assertEqual(lock.get_owner(), "task_1")

        # Task 2 cannot acquire while Task 1 owns it
        self.assertFalse(lock.acquire("task_2"))
        self.assertEqual(lock.get_owner(), "task_1")

        # Task 2 cannot release Task 1's lock
        lock.release("task_2")
        self.assertTrue(lock.is_locked())
        self.assertEqual(lock.get_owner(), "task_1")

        # Task 1 releases lock
        lock.release("task_1")
        self.assertFalse(lock.is_locked())
        self.assertIsNone(lock.get_owner())

        # Force release works
        self.assertTrue(lock.acquire("task_3"))
        lock.force_release()
        self.assertFalse(lock.is_locked())

    def test_atomic_save_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test_data.json"
            sample_data = {"repo": "docker", "status": "ok", "items": [1, 2, 3]}
            atomic_save_json(filepath, sample_data)

            self.assertTrue(filepath.exists())
            with open(filepath, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded, sample_data)

    def test_calculate_storage_forecast(self):
        repos = [
            {"id": "docker", "name": "Docker", "unique_csize": 1000000000},
            {"id": "immich", "name": "Immich", "unique_csize": 5000000000}
        ]
        archives = [
            {"name": "a1", "start": "2026-09-01T01:00:00", "deduplicated_size": 100000000},
            {"name": "a2", "start": "2026-09-02T01:00:00", "deduplicated_size": 120000000},
            {"name": "a3", "start": "2026-09-03T01:00:00", "deduplicated_size": 110000000}
        ]
        forecast = calculate_storage_forecast(repos, archives)
        self.assertIn("total_bytes", forecast)
        self.assertIn("free_bytes", forecast)
        self.assertIn("daily_growth_bytes", forecast)
        self.assertIn("days_until_full", forecast)
        self.assertIn("health_status", forecast)

    def test_parse_log_health(self):
        import main
        with tempfile.TemporaryDirectory() as tmpdir:
            orig_logs_dir = main.LOGS_DIR
            try:
                main.LOGS_DIR = Path(tmpdir)
                
                # Check with no log files
                health = main.parse_log_health()
                self.assertEqual(health["integrity_check"]["status"], "UNKNOWN")

                # Write a successful check_borg.log
                check_log = main.LOGS_DIR / "check_borg.log"
                check_log.write_text("[2026-09-20 04:00:01] [SUCCESS] Все репозитории проверены успешно\n", encoding="utf-8")

                health = main.parse_log_health()
                self.assertEqual(health["integrity_check"]["status"], "SUCCESS")
                self.assertEqual(health["integrity_check"]["timestamp"], "2026-09-20 04:00:01")

                # Write an error into sync_borg_yandex.log
                sync_log = main.LOGS_DIR / "sync_borg_yandex.log"
                sync_log.write_text("[2026-09-20 05:30:15] [ERROR] Сетевая ошибка при подключении к Yandex Disk\n", encoding="utf-8")

                health = main.parse_log_health()
                self.assertEqual(health["cloud_sync"]["status"], "ERROR")
                self.assertIn("Сетевая ошибка", health["cloud_sync"]["details"])
            finally:
                main.LOGS_DIR = orig_logs_dir

    def test_is_truthy(self):
        import main
        for val in ["true", "True", "1", 1, "yes", "YES", "on", "ON", True]:
            self.assertTrue(main.is_truthy(val), f"Failed for truthy {val}")
        for val in ["false", "False", "0", 0, "no", "off", None, "", "other"]:
            self.assertFalse(main.is_truthy(val), f"Failed for falsy {val}")

    def test_load_env_files(self):
        import main
        with tempfile.TemporaryDirectory() as tmpdir:
            test_env = Path(tmpdir) / ".env"
            test_env.write_text(
                "# Test comment\n"
                "BORG_TEST_KEY=hello_world\n"
                "BORG_AUTH_DISABLED='true'\n"
                "PORT=9999\n",
                encoding="utf-8"
            )
            main.load_env_files(extra_paths=[test_env])
            self.assertEqual(os.environ.get("BORG_TEST_KEY"), "hello_world")
            self.assertEqual(os.environ.get("BORG_AUTH_DISABLED"), "true")
            self.assertEqual(os.environ.get("PORT"), "9999")

if __name__ == "__main__":
    unittest.main()
