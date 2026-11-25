import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release_gate import (  # noqa: E402
    ReleaseGateError,
    enforce_release_gate,
    is_prerelease,
    repository_from_remote,
    require_green_ci,
)

COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUNS = {
    "workflow_runs": [
        {
            "id": 42,
            "head_sha": COMMIT,
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://github.com/x0c/agent-dbctl/actions/runs/42",
        }
    ]
}
JOBS = {
    "jobs": [
        {"name": "verify (ubuntu-latest)", "conclusion": "success"},
        {"name": "verify (macos-15)", "conclusion": "success"},
        {"name": "verify (windows-latest)", "conclusion": "success"},
        {"name": "server-smoke", "conclusion": "success"},
    ]
}


def completed(payload, returncode=0):
    return subprocess.CompletedProcess(
        args=["gh", "api"],
        returncode=returncode,
        stdout=json.dumps(payload) if returncode == 0 else "",
        stderr="simulated gh failure" if returncode else "",
    )


class ReleaseGateTests(unittest.TestCase):
    def test_stable_release_accepts_exact_green_commit_and_all_platforms(self):
        calls = []

        def runner(*args, **kwargs):
            calls.append(args[0][-1])
            return completed(RUNS if len(calls) == 1 else JOBS)

        attestation = enforce_release_gate("v0.6.0", "x0c/agent-dbctl", COMMIT, runner=runner)
        self.assertEqual(attestation["run_id"], 42)
        self.assertEqual(len(attestation["jobs"]), 4)
        self.assertIn(f"head_sha={COMMIT}", calls[0])
        self.assertIn("actions/runs/42/jobs", calls[1])

    def test_stable_release_rejects_red_or_pending_commit(self):
        payload = {
            "workflow_runs": [
                {"id": 41, "head_sha": COMMIT, "status": "completed", "conclusion": "failure"}
            ]
        }
        with self.assertRaisesRegex(ReleaseGateError, "completed/failure"):
            require_green_ci("x0c/agent-dbctl", COMMIT, runner=lambda *a, **k: completed(payload))

    def test_success_for_another_commit_does_not_attest_source(self):
        payload = {"workflow_runs": [{"id": 42, "head_sha": "f" * 40, "conclusion": "success"}]}
        with self.assertRaisesRegex(ReleaseGateError, "no completed run"):
            require_green_ci("x0c/agent-dbctl", COMMIT, runner=lambda *a, **k: completed(payload))

    def test_stable_release_rejects_missing_or_failed_platform_job(self):
        def runner(*args, **kwargs):
            endpoint = args[0][-1]
            if "/jobs?" in endpoint:
                payload = dict(JOBS)
                payload["jobs"] = JOBS["jobs"][:-2] + JOBS["jobs"][-1:]
                return completed(payload)
            return completed(RUNS)

        with self.assertRaisesRegex(ReleaseGateError, "windows-latest.*missing"):
            require_green_ci("x0c/agent-dbctl", COMMIT, runner=runner)

    def test_stable_release_fails_closed_when_github_is_unavailable(self):
        with self.assertRaisesRegex(ReleaseGateError, "simulated gh failure"):
            require_green_ci("x0c/agent-dbctl", COMMIT, runner=lambda *a, **k: completed({}, 1))

    def test_skip_ci_is_prerelease_only(self):
        with self.assertRaisesRegex(ReleaseGateError, "prerelease suffix"):
            enforce_release_gate(
                "v0.6.0",
                "x0c/agent-dbctl",
                COMMIT,
                skip_ci_check=True,
                runner=lambda *a, **k: self.fail("gh must not be called"),
            )
        self.assertIsNone(
            enforce_release_gate(
                "v0.6.0-rc.1",
                "x0c/agent-dbctl",
                COMMIT,
                skip_ci_check=True,
                runner=lambda *a, **k: self.fail("gh must not be called"),
            )
        )

    def test_prerelease_without_skip_still_uses_attestation_when_requested(self):
        def runner(*args, **kwargs):
            return completed(RUNS if "/jobs?" not in args[0][-1] else JOBS)

        self.assertIsNotNone(
            enforce_release_gate("v0.6.0-rc.1", "x0c/agent-dbctl", COMMIT, runner=runner)
        )

    def test_remote_parsing_and_prerelease_detection(self):
        for remote in (
            "https://github.com/x0c/agent-dbctl.git",
            "https://github.com/x0c/agent-dbctl",
            "git@github.com:x0c/agent-dbctl.git",
            "ssh://git@github.com/x0c/agent-dbctl.git",
        ):
            self.assertEqual(repository_from_remote(remote), "x0c/agent-dbctl")
        self.assertTrue(is_prerelease("v0.6.0-rc.1"))
        self.assertFalse(is_prerelease("v0.6.0"))
        with self.assertRaises(ReleaseGateError):
            repository_from_remote("git@example.com:x0c/agent-dbctl.git")


if __name__ == "__main__":
    unittest.main()
