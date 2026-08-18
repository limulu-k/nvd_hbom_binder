"""Evidence-audited, local-Git patch collection for upstream Clovery."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Callable


SUPPORTED_SUFFIXES = (".c", ".cc", ".cpp")


def reset_status(path: str | Path) -> None:
    Path(path).write_text("", encoding="utf-8")


def _status(path: str | Path, cve: str, url: str, status: str, **details: object) -> None:
    record = {
        "cve": str(cve).split("_", 1)[0],
        "url": url,
        "status": status,
        **details,
    }
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"collector: {record['cve']} {status}", flush=True)


def _clone_directory(root: str | Path, pack: str) -> Path | None:
    root = Path(root)
    exact = root / pack
    if exact.is_dir():
        return exact
    directories = [path for path in root.iterdir() if path.is_dir()]
    for directory in directories:
        if directory.name.lower() == pack.lower():
            return directory
    return directories[0] if len(directories) == 1 else None


def _commit_id(url: str) -> str | None:
    match = re.search(r"/commits?/([0-9a-fA-F]{7,40})(?:[/?#.]|$)", url)
    return match.group(1).lower() if match else None


def extract_local_diff(
    save_file: str,
    diff_root: str | Path,
    pack: str,
    clone_command: str,
    cve: str,
    url: str,
    *,
    clone_root: str | Path,
    status_path: str | Path,
    cloning_repo: Callable[[str, str], object],
) -> bool:
    """Clone once, resolve the commit locally, and retain supported source hunks."""

    if not pack or not clone_command:
        _status(status_path, cve, url, "invalid_repository_url")
        return False
    cloning_repo(pack, clone_command)
    repository = _clone_directory(clone_root, pack)
    if repository is None:
        _status(status_path, cve, url, "clone_unavailable")
        return False
    commit_id = _commit_id(url)
    if commit_id is None:
        _status(status_path, cve, url, "invalid_commit_url")
        return False
    resolved = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", f"{commit_id}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if resolved.returncode != 0:
        _status(status_path, cve, url, "commit_not_found", commit=commit_id)
        return False
    commit_id = resolved.stdout.strip().lower()
    parent_line = subprocess.run(
        ["git", "-C", str(repository), "rev-list", "--parents", "-n", "1", commit_id],
        capture_output=True,
        text=True,
        check=False,
    )
    parents = parent_line.stdout.split() if parent_line.returncode == 0 else []
    diff_command = (
        [
            "git", "-C", str(repository), "diff", "--find-renames",
            f"{commit_id}^1", commit_id,
        ]
        if len(parents) > 2
        else [
            "git", "-C", str(repository), "show", "--root", "--format=",
            "--find-renames", commit_id,
        ]
    )
    shown = subprocess.run(
        diff_command,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if shown.returncode != 0:
        _status(
            status_path,
            cve,
            url,
            "git_diff_failed",
            commit=commit_id,
            error=shown.stderr.strip()[-500:],
        )
        return False

    diff_body = shown.stdout
    save_text = diff_body.split("diff --git a", 1)[0] + "\n"
    kept_files: list[str] = []
    for chunk in diff_body.split("diff --git a")[1:]:
        changed = chunk.split("\n", 1)[0].split(" b/", 1)[0]
        if changed.lower().endswith(SUPPORTED_SUFFIXES):
            save_text += "diff --git a" + chunk + "\n"
            kept_files.append(changed)
    if not kept_files:
        _status(status_path, cve, url, "no_supported_source_diff", commit=commit_id)
        return False

    destination = Path(diff_root) / pack
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / save_file
    if target.is_file():
        _status(status_path, cve, url, "already_collected", commit=commit_id)
        return True
    target.write_text(
        f"PACK:{pack}\nCLONE:{clone_command}\nURL:{url}\n{save_text}",
        encoding="utf-8",
    )
    _status(status_path, cve, url, "collected", commit=commit_id, files=kept_files)
    return True
