#!/usr/bin/env python3
"""Build checksummed release packages locally from a committed tree."""
import argparse
import gzip
import hashlib
import os
import re
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("--version", required=True)
parser.add_argument("--source-commit", default="HEAD", help="reviewed commit with the same source tree")
args = parser.parse_args()

if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[a-z0-9.]+)?", args.version):
    parser.error("version must be a v-prefixed semantic version (e.g. v0.1.0)")
if subprocess.check_output(["git", "status", "--porcelain"], cwd=root).strip():
    parser.error("commit the releasable source tree first")

subprocess.run(["python3", "scripts/check-public.py"], cwd=root, check=True)

canonical_skill = (root / "skills" / "agent-dbctl" / "SKILL.md").read_text(encoding="utf-8").strip()
embedded_skill = (root / "cmd" / "agent-dbctl" / "skill.md").read_text(encoding="utf-8").strip()
if canonical_skill != embedded_skill:
    parser.error("cmd/agent-dbctl/skill.md is out of sync with skills/agent-dbctl/SKILL.md; run make sync-skill")

subprocess.run(["npm", "run", "build"], cwd=root / "web", check=True)

commit = subprocess.check_output(["git", "rev-parse", args.source_commit], cwd=root).decode().strip()
short_commit = subprocess.check_output(["git", "rev-parse", "--short", commit], cwd=root).decode().strip()
if subprocess.check_output(["git", "rev-parse", commit + "^{tree}"], cwd=root) != subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root):
    parser.error("source commit must have the same tree as HEAD")

epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", commit], cwd=root))
archive_time = datetime.fromtimestamp(epoch, timezone.utc).timetuple()[:6]

out = root / "dist" / args.version
out.mkdir(parents=True, exist_ok=True)
checksums = []
ldflags = f"-s -w -X main.version={args.version} -X main.buildCommit={short_commit}"

for platform in ("linux", "darwin", "windows"):
    for arch in ("amd64", "arm64"):
        name = "agent-dbctl" + (".exe" if platform == "windows" else "")
        binary = out / name
        env = dict(os.environ, GOOS=platform, GOARCH=arch, CGO_ENABLED="0", GOTOOLCHAIN="go1.26.11")
        with (out / f"build-{platform}-{arch}.log").open("w") as log:
            subprocess.run(
                ["go", "build", "-buildvcs=false", "-trimpath", "-ldflags", ldflags, "-o", str(binary), "./cmd/agent-dbctl"],
                cwd=root,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
        ext = "zip" if platform == "windows" else "tar.gz"
        archive = out / f"agent-dbctl_{args.version}_{platform}_{arch}.{ext}"
        assets = [
            (binary, name),
            (root / "LICENSE", "LICENSE"),
            (root / "README.md", "README.md"),
            (root / "skills" / "agent-dbctl" / "SKILL.md", "SKILL.md"),
        ]
        if platform == "windows":
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as target:
                for source, target_name in assets:
                    info = zipfile.ZipInfo(target_name, date_time=archive_time)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (0o755 if target_name == name else 0o644) << 16
                    target.writestr(info, source.read_bytes())
        else:
            def private_header(info):
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = epoch
                info.pax_headers = {}
                info.mode = 0o755 if info.name == name else 0o644
                return info

            with archive.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as target:
                    for source, target_name in assets:
                        target.add(source, arcname=target_name, filter=private_header)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {archive.name}")
        binary.unlink()
        print(f"{archive.name}  {digest}", flush=True)

(out / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
(out / "SOURCE_COMMIT").write_text(commit + "\n", encoding="utf-8")
print(f"Built {len(checksums)} release archives in {out.relative_to(root)} from commit {commit}.")
