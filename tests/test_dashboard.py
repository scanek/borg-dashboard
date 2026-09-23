import os
import sys
import unittest
import tempfile
import json
from pathlib import Path

# Add app directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from main import (
    format_bytes, RepoLock, atomic_save_json, calculate_storage_forecast,
    hash_password, verify_password, TaskLogBuffer,
    record_failed_auth, reset_failed_auth, is_auth_rate_limited,
    _parse_status_log
)

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

    def test_password_hashing_and_verification(self):
        pw = "SuperSecurePassword123!"
        pw_hash, salt = hash_password(pw)
        self.assertTrue(pw_hash)
        self.assertTrue(salt)
        self.assertEqual(len(salt), 32)
        # Correct password verifies
        self.assertTrue(verify_password(pw, pw_hash, salt))
        # Wrong password fails
        self.assertFalse(verify_password("WrongPassword!", pw_hash, salt))
        self.assertFalse(verify_password("", pw_hash, salt))
        # Deterministic with same salt
        hash2, _ = hash_password(pw, salt=salt)
        self.assertEqual(pw_hash, hash2)

    def test_task_log_buffer_monotonic_seq(self):
        buf = TaskLogBuffer(maxlen=5)
        self.assertEqual(len(buf), 0)

        # Append 3 lines
        buf.append("line 1")
        buf.append("line 2")
        buf.append("line 3")
        self.assertEqual(len(buf), 3)

        # Retrieve all lines from seq 0
        items = buf.get_lines_since(0)
        self.assertEqual(len(items), 3)
        self.assertEqual([seq for seq, _ in items], [1, 2, 3])
        self.assertEqual([line for _, line in items], ["line 1", "line 2", "line 3"])

        # No new lines since seq 3
        empty = buf.get_lines_since(3)
        self.assertEqual(len(empty), 0)

        # Append 5 more lines (total 8 lines, buffer capacity 5)
        # Ring buffer should drop lines 1, 2, 3 and keep 4, 5, 6, 7, 8
        buf.append("line 4")
        buf.append("line 5")
        buf.append("line 6")
        buf.append("line 7")
        buf.append("line 8")
        self.assertEqual(len(buf), 5)

        # Consumer asking for lines since seq 3 gets 4, 5, 6, 7, 8
        new_items = buf.get_lines_since(3)
        self.assertEqual(len(new_items), 5)
        self.assertEqual([seq for seq, _ in new_items], [4, 5, 6, 7, 8])
        self.assertEqual([line for _, line in new_items], ["line 4", "line 5", "line 6", "line 7", "line 8"])

        # Late-joining consumer asking from seq 0 gets available 5 lines (4 to 8)
        late_items = buf.get_lines_since(0)
        self.assertEqual(len(late_items), 5)
        self.assertEqual(late_items[0][0], 4)
        self.assertEqual(late_items[-1][0], 8)

    def test_auth_rate_limiter(self):
        ip = "192.168.1.99"
        reset_failed_auth(ip)
        self.assertFalse(is_auth_rate_limited(ip))

        # Record 4 failed attempts -> still not limited (< 5)
        for _ in range(4):
            record_failed_auth(ip)
        self.assertFalse(is_auth_rate_limited(ip))

        # 5th attempt -> triggers rate limiting
        record_failed_auth(ip)
        self.assertTrue(is_auth_rate_limited(ip))

        # Resetting failed auth clears rate limiting
        reset_failed_auth(ip)
        self.assertFalse(is_auth_rate_limited(ip))

    def test_parse_status_log_helper(self):
        import main
        with tempfile.TemporaryDirectory() as tmpdir:
            orig_logs_dir = main.LOGS_DIR
            try:
                main.LOGS_DIR = Path(tmpdir)

                # Non-existent file
                res_missing = _parse_status_log("non_existent.log", r"\[(.*?)\]\s+\[SUCCESS\]\s+(.*)", "Success")
                self.assertEqual(res_missing["status"], "UNKNOWN")

                # File with success
                log_file = Path(tmpdir) / "test_status.log"
                log_file.write_text("[2026-09-23 12:00:00] [SUCCESS] All checks passed\n", encoding="utf-8")
                res_ok = _parse_status_log("test_status.log", r"\[(.*?)\]\s+\[SUCCESS\]\s+(.*)", lambda m: m.group(2))
                self.assertEqual(res_ok["status"], "SUCCESS")
                self.assertEqual(res_ok["timestamp"], "2026-09-23 12:00:00")
                self.assertEqual(res_ok["details"], "All checks passed")

                # File with error
                log_file.write_text("[2026-09-23 12:10:00] [ERROR] Disk usage above 80%\n", encoding="utf-8")
                res_err = _parse_status_log("test_status.log", r"\[(.*?)\]\s+\[SUCCESS\]\s+(.*)", "Success")
                self.assertEqual(res_err["status"], "ERROR")
                self.assertIn("Disk usage", res_err["details"])
            finally:
                main.LOGS_DIR = orig_logs_dir

    def test_csrf_middleware(self):
        from fastapi.testclient import TestClient
        import main
        client = TestClient(main.app)

        # Cross-site mutation request must be rejected with 403
        res = client.post("/api/refresh", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("CSRF", res.text)

        # Request with X-Dashboard-Request passes CSRF check
        res2 = client.post("/api/refresh", headers={"X-Dashboard-Request": "1"})
        self.assertNotEqual(res2.status_code, 403)

    def test_cancel_action_api(self):
        from fastapi.testclient import TestClient
        import threading
        import main
        client = TestClient(main.app)

        orig_auth_disabled = main.BORG_AUTH_DISABLED
        try:
            main.BORG_AUTH_DISABLED = True
            # Cancel unknown task returns 404
            res_404 = client.post("/api/actions/cancel/non-existent-task-id", headers={"X-Dashboard-Request": "1"})
            self.assertEqual(res_404.status_code, 404)

            # Register mock running task
            task_id = "test-mock-task-123"
            main.ACTION_TASKS[task_id] = {
                "process": None,
                "status": "running",
                "lock": threading.Lock(),
                "lines": main.TaskLogBuffer(),
                "created_at": 1000.0,
                "repo_id": None
            }
            res_cancel = client.post(f"/api/actions/cancel/{task_id}", headers={"X-Dashboard-Request": "1"})
            self.assertEqual(res_cancel.status_code, 200)
            data = res_cancel.json()
            self.assertEqual(data["status"], "cancelled")
            self.assertEqual(main.ACTION_TASKS[task_id]["status"], "failed")
            self.assertEqual(main.ACTION_TASKS[task_id]["exit_code"], -15)
        finally:
            main.BORG_AUTH_DISABLED = orig_auth_disabled

if __name__ == "__main__":
    unittest.main()
