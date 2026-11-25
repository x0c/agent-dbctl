import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server_smoke import compose_up_with_network_retry  # noqa: E402


def result(code, output):
    return subprocess.CompletedProcess(["docker", "compose"], code, stdout=output, stderr="")


class ComposeRetryTests(unittest.TestCase):
    @patch("server_smoke.time.sleep")
    @patch("server_smoke.subprocess.run")
    def test_network_failures_retry_with_bounded_backoff(self, run, sleep):
        run.side_effect = [
            result(1, "failed to fetch anonymous token: EOF"),
            result(1, "TLS handshake timeout"),
            result(0, "started"),
        ]
        compose_up_with_network_retry(["docker", "compose"])
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 10])

    @patch("server_smoke.time.sleep")
    @patch("server_smoke.subprocess.run")
    def test_product_failure_does_not_retry(self, run, sleep):
        run.return_value = result(1, "invalid OIDC configuration")
        with self.assertRaises(subprocess.CalledProcessError):
            compose_up_with_network_retry(["docker", "compose"])
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    @patch("server_smoke.time.sleep")
    @patch("server_smoke.subprocess.run")
    def test_persistent_network_failure_stops_after_three_attempts(self, run, sleep):
        run.return_value = result(1, "unexpected EOF")
        with self.assertRaises(subprocess.CalledProcessError):
            compose_up_with_network_retry(["docker", "compose"])
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    @patch("server_smoke.time.sleep")
    @patch("server_smoke.subprocess.run")
    def test_success_does_not_retry(self, run, sleep):
        run.return_value = result(0, "started")
        compose_up_with_network_retry(["docker", "compose"])
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
