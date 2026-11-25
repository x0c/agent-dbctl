#!/usr/bin/env python3
"""Run the packaged Linux C/S, OIDC, CLI approval, and audit path in Compose."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class SmokeFailure(RuntimeError):
    pass


class Browser:
    def __init__(self) -> None:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            NoRedirect(),
        )

    def request(self, method: str, url: str, body=None, csrf: str = ""):
        raw = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=raw, method=method)
        req.add_header("Origin", urlsplit_origin(url))
        req.add_header("Accept", "application/json")
        if raw is not None:
            req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-Agent-DBCTL-CSRF", csrf)
        try:
            with self.opener.open(req, timeout=15) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as response:
            return response.code, response.read(), response.headers


def urlsplit_origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def compose_up_with_network_retry(compose: list[str]) -> None:
    markers = (
        "failed to fetch anonymous token",
        "unexpected eof",
        ": eof",
        "i/o timeout",
        "tls handshake timeout",
        "temporary failure in name resolution",
        "network is unreachable",
    )
    command = compose + ["up", "-d", "--build"]
    for attempt in range(1, 4):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900, check=False)
        output = (result.stdout or "") + (result.stderr or "")
        print(output, end="", flush=True)
        if result.returncode == 0:
            return
        error = subprocess.CalledProcessError(result.returncode, command, output=result.stdout, stderr=result.stderr)
        if attempt == 3 or not any(marker in output.lower() for marker in markers):
            raise error
        print(f"Docker network failure; retrying build ({attempt + 1}/3)", flush=True)
        time.sleep(5 * attempt)


def json_body(raw: bytes):
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SmokeFailure(f"invalid JSON response: {raw[:500]!r}") from exc


def wait_health(url: str, attempts: int = 120) -> None:
    for _ in range(attempts):
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=2) as response:
                if response.status == 200 and json.loads(response.read()).get("status") == "running":
                    return
        except Exception:
            pass
        time.sleep(1)
    raise SmokeFailure(f"server did not become healthy: {url}")


def oidc_login(browser: Browser, base: str, oidc_port: int) -> str:
    status, raw, headers = browser.request("GET", base + "/api/v1/auth/oidc/login?return_to=/")
    expect(status == 302, f"OIDC login start returned {status}: {raw[:500]!r}")
    location = headers.get("Location", "")
    parsed = urllib.parse.urlsplit(location)
    expect(parsed.hostname == "oidc" and parsed.port == 8081, f"unexpected OIDC authorization URL: {location}")
    provider_url = urllib.parse.urlunsplit(("http", f"127.0.0.1:{oidc_port}", parsed.path, parsed.query, ""))
    status, raw, headers = browser.request("GET", provider_url)
    expect(status == 302, f"OIDC fixture authorize returned {status}: {raw[:500]!r}")
    callback = urllib.parse.urljoin(base + "/", headers.get("Location", ""))
    status, raw, headers = browser.request("GET", callback)
    expect(status == 302 and headers.get("Location") == "/", f"OIDC callback failed: {status} {raw[:500]!r}")
    status, raw, _ = browser.request("GET", base + "/api/v1/bootstrap")
    bootstrap = json_body(raw)
    expect(status == 200 and bootstrap.get("authenticated") is True, f"OIDC bootstrap failed: {status} {bootstrap}")
    expect(bootstrap.get("ui_csrf_token"), "OIDC bootstrap omitted CSRF token")
    return bootstrap["ui_csrf_token"]


def cli_device_login(binary: Path, config_home: Path, oidc_port: int, browser: Browser) -> None:
    import pty

    env = client_env(config_home)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(str(binary), [str(binary), "--context", "smoke", "login"], env)
    output = b""
    code = None
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and code is None:
            ready, _, _ = select.select([fd], [], [], 1)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError as exc:
                raise SmokeFailure(f"CLI login exited before showing a device code: {output!r}") from exc
            if not chunk:
                break
            output += chunk
            match = re.search(rb"\b([A-Z0-9]{4}-[A-Z0-9]{4})\b", output)
            if match:
                code = match.group(1).decode()
        expect(code is not None, f"CLI did not emit a device confirmation code: {output!r}")
        status, raw, _ = browser.request(
            "POST",
            f"http://127.0.0.1:{oidc_port}/device",
            {"user_code": code, "decision": "approve"},
        )
        expect(status == 200, f"device confirmation failed: {status} {raw[:500]!r}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            finished, status_code = os.waitpid(pid, os.WNOHANG)
            if finished == pid:
                expect(os.waitstatus_to_exitcode(status_code) == 0, f"CLI login failed: {output!r}")
                return
            ready, _, _ = select.select([fd], [], [], 1)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    continue
                if chunk:
                    output += chunk
        raise SmokeFailure(f"CLI login did not finish after approval: {output!r}")
    finally:
        os.close(fd)
        try:
            finished, _ = os.waitpid(pid, os.WNOHANG)
            if finished == 0:
                os.kill(pid, 15)
                os.waitpid(pid, 0)
        except ChildProcessError:
            pass


def client_env(config_home: Path) -> dict[str, str]:
    return dict(
        os.environ,
        AGENT_DBCTL_CONFIG_HOME=str(config_home),
        AGENT_DBCTL_SECRET_BACKEND="file",
        AGENT_DBCTL_NO_BROWSER="1",
        AGENT_DBCTL_NO_SKILL_SYNC="1",
        AGENT_DBCTL_SMOKE_DB_PASSWORD="synthetic-smoke-password",
    )


def run_cli(binary: Path, config_home: Path, *args: str, expected=(0,)):
    result = subprocess.run(
        [str(binary), "--context", "smoke", *args, "--json"],
        env=client_env(config_home),
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SmokeFailure(
            f"CLI {args} returned invalid JSON (exit {result.returncode}): {result.stdout!r} {result.stderr!r}"
        ) from exc
    if result.returncode not in expected:
        raise SmokeFailure(f"CLI {args} exited {result.returncode}: {payload} stderr={result.stderr!r}")
    return result.returncode, payload


def approve_execution(binary: Path, config_home: Path, base: str, sql: str, reason: str,
                      admin: Browser, admin_csrf: str, approver: Browser, approver_csrf: str) -> None:
    code, payload = run_cli(
        binary,
        config_home,
        "exec",
        "--db",
        "prod-smoke",
        "--wait=false",
        "--reason",
        reason,
        "--sql",
        sql,
        expected=(7,),
    )
    error = payload.get("error") or {}
    context = error.get("context") or {}
    operation_id = context.get("operation_id")
    approval_id = context.get("approval_id")
    expect(code == 7 and error.get("code") == "waiting_approval" and operation_id and approval_id,
           f"write did not pause for approval: {payload}")

    status, raw, _ = admin.request(
        "POST", base + f"/api/v1/approvals/{approval_id}/approve", {"note": "self approval attempt"}, admin_csrf
    )
    expect(status == 403, f"four-eyes self-approval returned {status}: {raw[:500]!r}")
    status, raw, _ = approver.request(
        "POST", base + f"/api/v1/approvals/{approval_id}/approve", {"note": "verified synthetic smoke change"}, approver_csrf
    )
    expect(status == 200, f"independent approver failed: {status} {raw[:500]!r}")
    _, waited = run_cli(binary, config_home, "op", "wait", operation_id, "--timeout", "30s")
    expect((waited.get("data") or {}).get("status") == "succeeded", f"approved operation did not succeed: {waited}")


def run(args) -> None:
    binary = args.binary.resolve()
    expect(binary.is_file(), f"CLI binary does not exist: {binary}")
    base = f"http://127.0.0.1:{args.port}"
    project = f"agent-dbctl-smoke-{os.getpid()}"
    image = f"agent-dbctl-smoke:{os.getpid()}"
    compose = [
        "docker", "compose", "-p", project,
        "-f", str(ROOT / "compose.yaml"),
        "-f", str(ROOT / "deploy" / "compose.smoke.yaml"),
    ]
    with tempfile.TemporaryDirectory(prefix="agent-dbctl-smoke-") as tmp:
        temp = Path(tmp)
        env_file = temp / "compose.env"
        env_file.write_text(
            "POSTGRES_DB=agentdbctl\n"
            "POSTGRES_USER=agentdbctl\n"
            f"POSTGRES_PASSWORD={secrets.token_hex(24)}\n"
            f"AGENT_DBCTL_REDIS_PASSWORD={secrets.token_hex(24)}\n"
            f"AGENT_DBCTL_MASTER_KEY={secrets.token_hex(32)}\n"
            f"AGENT_DBCTL_BOOTSTRAP_ADMIN_PASSWORD={secrets.token_urlsafe(24)}\n"
            f"AGENT_DBCTL_OIDC_SECRET={secrets.token_urlsafe(24)}\n"
            f"AGENT_DBCTL_BIND_ADDR=127.0.0.1:{args.port}\n"
            f"AGENT_DBCTL_PUBLIC_URL={base}\n"
            f"SMOKE_OIDC_BIND_ADDR=127.0.0.1:{args.oidc_port}\n"
            f"SMOKE_PUBLIC_OIDC_URL=http://127.0.0.1:{args.oidc_port}\n"
            f"AGENT_DBCTL_IMAGE={image}\n"
            "AGENT_DBCTL_VERSION=smoke\n"
            "AGENT_DBCTL_COMMIT=smoke\n",
            encoding="utf-8",
        )
        env_file.chmod(0o600)
        compose += ["--env-file", str(env_file)]
        try:
            compose_up_with_network_retry(compose)
            wait_health(base + "/healthz")

            admin = Browser()
            admin_csrf = oidc_login(admin, base, args.oidc_port)
            approver_password = secrets.token_urlsafe(24)
            status, raw, _ = admin.request(
                "POST", base + "/api/v1/users",
                {"email": "approver@example.com", "display_name": "Smoke Approver", "password": approver_password},
                admin_csrf,
            )
            approver_user = json_body(raw)
            expect(status == 200 and approver_user.get("id"), f"create approver failed: {status} {approver_user}")

            config_home = temp / "client"
            run_cli(binary, config_home, "context", "add", "smoke", "--endpoint", base, "--auth", "oidc_device", "--use")
            cli_device_login(binary, config_home, args.oidc_port, admin)
            _, who = run_cli(binary, config_home, "whoami")
            expect((who.get("data") or {}).get("kind") == "human", f"CLI login did not mint a human principal: {who}")

            _, added = run_cli(
                binary, config_home, "db", "add",
                "--engine", "sqlite",
                "--host", "/var/lib/agent-dbctl/smoke.db",
                "--database", "/var/lib/agent-dbctl/smoke.db",
                "--system", "smoke",
                "--env", "prod",
                "--alias", "prod-smoke",
                "--access-level", "read_write",
                "--user", "smoke",
                "--secret-env", "AGENT_DBCTL_SMOKE_DB_PASSWORD",
                "--no-workspace",
            )
            target = (added.get("data") or {}).get("target") or {}
            expect(target.get("ref") == "smoke/prod/smoke" and target.get("alias") == "prod-smoke",
                   f"unexpected smoke target: {added}")

            status, raw, _ = admin.request("GET", base + "/api/v1/systems")
            systems = json_body(raw).get("items", [])
            system_id = next((item.get("id") for item in systems if item.get("slug") == "smoke"), None)
            expect(status == 200 and system_id, f"smoke system lookup failed: {status} {systems}")
            status, raw, _ = admin.request(
                "POST", base + "/api/v1/roles",
                {"user_id": approver_user["id"], "role": "approver", "scope_type": "system", "scope_id": system_id},
                admin_csrf,
            )
            expect(status == 200, f"approver role binding failed: {status} {raw[:500]!r}")

            approver = Browser()
            status, raw, _ = approver.request(
                "POST", base + "/api/v1/auth/login",
                {"email": "approver@example.com", "password": approver_password},
            )
            approver_login = json_body(raw)
            expect(status == 200 and approver_login.get("ui_csrf_token"), f"approver login failed: {status} {approver_login}")
            approver_csrf = approver_login["ui_csrf_token"]

            approve_execution(
                binary, config_home, base,
                "CREATE TABLE smoke_items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
                "Create isolated Linux smoke table",
                admin, admin_csrf, approver, approver_csrf,
            )
            approve_execution(
                binary, config_home, base,
                "INSERT INTO smoke_items (id, name) VALUES (1, 'linux-compose-oidc')",
                "Insert isolated Linux smoke row",
                admin, admin_csrf, approver, approver_csrf,
            )
            _, selected = run_cli(
                binary, config_home, "exec", "--db", "prod-smoke",
                "--sql", "SELECT id, name FROM smoke_items WHERE id = 1 LIMIT 1",
            )
            expect("linux-compose-oidc" in json.dumps(selected), f"readback missed approved row: {selected}")
            _, audit = run_cli(binary, config_home, "audit", "verify")
            audit_data = audit.get("data") or {}
            expect(audit_data.get("valid") is True and audit_data.get("checked_count", 0) >= 10,
                   f"audit chain verification failed: {audit}")
            print(json.dumps({
                "ok": True,
                "deployment": "linux-compose",
                "control_plane": "postgres",
                "event_result_bus": "redis",
                "web_oidc": "RS256+PKCE",
                "cli_login": "oidc-rfc8628-device-flow",
                "approvals": 2,
                "audit_entries": audit_data["checked_count"],
                "target": target["ref"],
            }, indent=2))
        except Exception:
            subprocess.run(compose + ["logs", "--no-color"], cwd=ROOT, check=False, timeout=60)
            raise
        finally:
            subprocess.run(compose + ["down", "-v", "--remove-orphans"], cwd=ROOT, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            subprocess.run(["docker", "image", "rm", "-f", image], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "dist" / "agent-dbctl")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--oidc-port", type=int, default=18081)
    args = parser.parse_args()
    for port in (args.port, args.oidc_port):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError as exc:
                parser.error(f"required loopback port {port} is unavailable: {exc}")
    try:
        run(args)
    except (SmokeFailure, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"SERVER_SMOKE_FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
