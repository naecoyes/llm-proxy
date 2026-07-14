import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from health_checker import HealthChecker
from request_logger import RequestLogger
from smart_batch_monitor import set_smart_batch_parallel
from usage_controller import UsageController


class HealthStateConcurrencyTests(unittest.TestCase):
    def test_network_circuit_opens_after_three_transient_failures_and_resets_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = HealthChecker(
                {"failover": {"network_circuit_threshold": 3, "network_circuit_cooldown_seconds": 1}},
                tmp,
            )
            checker.initialize_model("model-a")
            checker.record_transient_failure("model-a", "temporary DNS error")
            checker.record_transient_failure("model-a", "temporary DNS error")
            self.assertTrue(checker.is_healthy("model-a"))

            checker.record_transient_failure("model-a", "temporary DNS error")
            state = checker.health_state["model-a"]
            self.assertFalse(checker.is_healthy("model-a"))
            self.assertEqual(state.circuit_state, "open")
            self.assertEqual(state.transient_failures, 3)

            checker.mark_healthy("model-a")
            state = checker.health_state["model-a"]
            self.assertTrue(checker.is_healthy("model-a"))
            self.assertEqual(state.circuit_state, "closed")
            self.assertEqual(state.transient_failures, 0)

    def test_concurrent_updates_are_atomic_and_persist_complete_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = HealthChecker({}, tmp)
            checker.initialize_model("model-a")
            checker.set_re_enable_time("model-a", 12345.0, "cooldown")

            threads = [
                threading.Thread(
                    target=checker.record_transient_failure,
                    args=("model-a", "temporary"),
                )
                for _ in range(12)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            payload = json.loads(
                (Path(tmp) / "health_state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["model-a"]["total_failures"], 12)
            self.assertEqual(len(payload["model-a"]["recent_results"]), 12)
            self.assertEqual(payload["model-a"]["re_enable_at"], 12345.0)

            restored = HealthChecker({}, tmp)
            self.assertEqual(restored.health_state["model-a"].re_enable_at, 12345.0)
            self.assertEqual(len(restored.health_state["model-a"].recent_results), 12)


class UsageConcurrencyTests(unittest.TestCase):
    def test_concurrent_acquire_never_exceeds_model_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            controller = UsageController(
                {
                    "usage": {
                        "per_model_limits": {
                            "model-a": {"max_concurrent": 2}
                        }
                    }
                },
                tmp,
            )
            barrier = threading.Barrier(10)
            observed = []
            observed_lock = threading.Lock()

            def worker():
                barrier.wait()
                acquired = controller.acquire_model("model-a")
                if acquired:
                    with observed_lock:
                        observed.append(
                            controller.rate_limit_states["model-a"].active_requests
                        )
                    time.sleep(0.01)
                    controller.release_model("model-a")

            threads = [threading.Thread(target=worker) for _ in range(10)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertTrue(observed)
            self.assertLessEqual(max(observed), 2)
            self.assertEqual(
                controller.rate_limit_states["model-a"].active_requests,
                0,
            )


class SmartBatchControlTests(unittest.TestCase):
    def test_parallel_control_is_written_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            batch_id = "smart-batch-test"
            state = {
                "batch_id": batch_id,
                "status": "running",
                "updated_at": "2099-01-01T00:00:00+00:00",
                "parallel": 3,
                "effective_parallel": 2,
                "tasks": [{"status": "running", "strix_pid": os.getpid()}],
            }
            (state_dir / f"{batch_id}.json").write_text(
                json.dumps(state),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"STRIX_BATCH_STATE_DIR": tmp}):
                updated = set_smart_batch_parallel(batch_id, 4)

            control = json.loads(
                (state_dir / f"{batch_id}.control.json").read_text(encoding="utf-8")
            )
            self.assertEqual(control["parallel"], 4)
            self.assertEqual(updated["parallel_control"]["parallel"], 4)


class RequestLifecycleTests(unittest.TestCase):
    def test_pending_request_from_previous_process_is_interrupted(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = RequestLogger(tmp)
            logger.process_started_at = datetime.now().astimezone()
            old_timestamp = (datetime.now().astimezone() - timedelta(minutes=5)).isoformat()

            joined = logger.join_logs(
                [
                    {
                        "type": "request",
                        "request_id": "old-request",
                        "timestamp": old_timestamp,
                        "actual_model": "model-a",
                    }
                ]
            )["requests"][0]

            self.assertEqual(joined["status"], "interrupted")
            self.assertIn("restarted", joined["error"])


if __name__ == "__main__":
    unittest.main()
