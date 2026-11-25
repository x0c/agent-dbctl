#!/usr/bin/env python3
"""Fail-closed CI attestation for stable agent-dbctl release archives."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Callable

REQUIRED_JOBS = {
    "verify (ubuntu-latest)",
    "verify (macos-15)",
    "verify (windows-latest)",
    "server-smoke",
}


class ReleaseGateError(RuntimeError):
    pass


Runner = Callable[..., subprocess.CompletedProcess[str]]


def is_prerelease(version: str) -> bool:
    return "-" in version


def repository_from_remote(remote: str) -> str:
    value = remote.strip()
    patterns = (
        r"^https://github\.com/(?P<repo>[^/]+/[^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:(?P<repo>[^/]+/[^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/(?P<repo>[^/]+/[^/]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, value)
        if match:
            return match.group("repo")
    raise ReleaseGateError(
        "cannot derive a GitHub repository from origin; pass --repository owner/name"
    )


def _gh_json(runner: Runner, endpoint: str) -> dict[str, Any]:
    result = runner(
        ["gh", "api", endpoint],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown gh error").strip()
        raise ReleaseGateError(f"GitHub CI attestation query failed: {detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleaseGateError("GitHub CI attestation returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ReleaseGateError("GitHub CI attestation returned an unexpected payload")
    return payload


def require_green_ci(
    repository: str,
    commit: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository):
        raise ReleaseGateError("repository must use owner/name form")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ReleaseGateError("source commit must be a full 40-character Git SHA")

    encoded_repo = "/".join(repository.split("/"))
    payload = _gh_json(
        runner,
        f"repos/{encoded_repo}/actions/workflows/ci.yml/runs"
        f"?head_sha={commit}&status=completed&per_page=100",
    )
    runs = payload.get("workflow_runs", [])
    if not isinstance(runs, list):
        raise ReleaseGateError("GitHub CI response omitted workflow_runs")
    matching = [
        run
        for run in runs
        if isinstance(run, dict) and run.get("head_sha", "").lower() == commit.lower()
    ]
    successful = next((run for run in matching if run.get("conclusion") == "success"), None)
    if successful is None:
        states = ", ".join(
            f"{run.get('status', 'unknown')}/{run.get('conclusion') or 'pending'}"
            for run in matching[:3]
        ) or "no completed run"
        raise ReleaseGateError(
            f"stable release blocked: CI has no successful run for {commit} ({states})"
        )

    run_id = successful.get("id")
    if not isinstance(run_id, int):
        raise ReleaseGateError("successful CI run has no numeric id")
    jobs_payload = _gh_json(
        runner,
        f"repos/{encoded_repo}/actions/runs/{run_id}/jobs?per_page=100",
    )
    jobs = jobs_payload.get("jobs", [])
    if not isinstance(jobs, list):
        raise ReleaseGateError("GitHub CI response omitted jobs")
    by_name = {
        job.get("name"): job.get("conclusion")
        for job in jobs
        if isinstance(job, dict)
    }
    insufficient = {
        name: by_name.get(name) or "missing"
        for name in sorted(REQUIRED_JOBS)
        if by_name.get(name) != "success"
    }
    if insufficient:
        details = ", ".join(f"{name}={state}" for name, state in insufficient.items())
        raise ReleaseGateError(
            f"stable release blocked: CI run {run_id} lacks green platform jobs ({details})"
        )
    return {
        "repository": repository,
        "commit": commit,
        "run_id": run_id,
        "url": successful.get("html_url", ""),
        "jobs": {name: by_name[name] for name in sorted(REQUIRED_JOBS)},
    }


def enforce_release_gate(
    version: str,
    repository: str,
    commit: str,
    skip_ci_check: bool = False,
    runner: Runner = subprocess.run,
) -> dict[str, Any] | None:
    if skip_ci_check:
        if not is_prerelease(version):
            raise ReleaseGateError(
                "--skip-ci-check is allowed only for versions with a prerelease suffix"
            )
        return None
    return require_green_ci(repository, commit, runner)
