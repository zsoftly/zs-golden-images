#!/usr/bin/env python3
"""Measure installed Ansible collections, including added files and link targets."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def tree_digest(root, require_root=True):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Collection root must be a real directory")
    resolved = root.resolve()
    entries = []
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        if require_root and (info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022)):
            raise ValueError("Collection contents must be root-owned and protected")
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute() or not path.resolve(strict=True).is_relative_to(resolved):
                raise ValueError("Collection symlink escapes its collection")
            entries.append([relative, "link", target])
        elif path.is_file():
            entries.append([relative, "file", stat.S_IMODE(info.st_mode), hashlib.sha256(path.read_bytes()).hexdigest()])
        elif path.is_dir():
            entries.append([relative, "directory", stat.S_IMODE(info.st_mode)])
        else:
            raise ValueError("Unexpected file type in collection")
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()


def inventory(base, pins, require_root=True):
    base = Path(base)
    if require_root:
        for parent in [base, *base.parents]:
            info = parent.lstat()
            if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("Collection ancestry must be root-owned and protected")
    result = {}
    for pin in pins:
        namespace, name = pin["name"].split(".")
        root = base / "ansible_collections" / namespace / name
        for parent in [root.parent, root.parent.parent]:
            info = parent.lstat()
            if parent.is_symlink() or (require_root and (info.st_uid != 0 or info.st_mode & 0o022)):
                raise ValueError("Collection namespace must be real, root-owned and protected")
        manifest = json.loads((root / "MANIFEST.json").read_text())["collection_info"]
        if (manifest["namespace"], manifest["name"], manifest["version"]) != (namespace, name, pin["version"]):
            raise ValueError("Installed collection identity does not match reviewed pin")
        result[pin["name"]] = {"version": pin["version"], "artifact_sha256": pin["sha256"], "tree_sha256": tree_digest(root, require_root)}
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: collection_integrity.py /absolute/collections pins-json")
    print(json.dumps(inventory(sys.argv[1], json.loads(sys.argv[2])), sort_keys=True))
