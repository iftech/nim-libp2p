#!/usr/bin/env python3
"""Add or move nimbus-eth2 vendor submodules to the nim-libp2p lock when a requirement is unmet.

Walks the requirements transitively: each vendored dependency's own .nimble is checked too.

Usage: align_nimbus_vendor.py <nimbus-eth2 dir>
"""

import configparser
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


def load_lock_checker():
    path = Path(__file__).with_name("check-nimble-lock.py")
    spec = importlib.util.spec_from_file_location("check_nimble_lock", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repo_key(url):
    return Path(urlparse(url).path).name.lower().removesuffix(".git")


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE, text=True
    ).stdout.strip()


def vendor_submodules(nimbus):
    parser = configparser.ConfigParser()
    if not parser.read(nimbus / ".gitmodules"):
        raise SystemExit(f"{nimbus}/.gitmodules not found: not a nimbus-eth2 checkout")
    return {
        repo_key(parser[section]["url"]): parser[section]["path"]
        for section in parser.sections()
        if parser[section].get("path", "").startswith("vendor/")
    }


def nimble_file(package_dir):
    return next(package_dir.glob("*.nimble"), None)


def nimble_version(package_dir):
    nimble = nimble_file(package_dir)
    if nimble is None:
        return None
    match = re.search(r'^version\s*=\s*"([^"]+)"', nimble.read_text(), re.M)
    return match.group(1) if match else None


def nimble_requirements(checker, package_dir):
    nimble = nimble_file(package_dir)
    return checker.read_requirements(nimble) if nimble else []


def satisfied(checker, version, requirement):
    try:
        return version is not None and checker.satisfies(version, requirement)
    except ValueError:
        return False


def checkout(repo_dir, url, revision):
    git(repo_dir, "fetch", "--quiet", url, revision)
    git(repo_dir, "checkout", "--quiet", revision)
    git(repo_dir, "submodule", "update", "--init", "--recursive", "--quiet")


def add_submodule(nimbus, url, revision):
    path = f"vendor/{repo_key(url)}"
    git(nimbus, "submodule", "add", "--quiet", url, path)
    checkout(nimbus / path, url, revision)
    return path


def align_requirement(nimbus, checker, packages, submodules, requirement, changes):
    name = checker.package_name(requirement)
    locked = packages.get(name)
    if locked is None:
        print(f"warning: {name} is missing from nix/libp2p.lock", file=sys.stderr)
        return None, False

    url = locked["url"]
    path = submodules.get(repo_key(url))
    if path is None:
        path = add_submodule(nimbus, url, locked["vcsRevision"])
        submodules[repo_key(url)] = path
        changes.append(f"{path}: added at {locked.get('version', '?')}")
        return path, True

    version = nimble_version(nimbus / path)
    if satisfied(checker, version, requirement):
        return path, False

    lock_version = locked.get("version")
    if not satisfied(checker, lock_version, requirement):
        print(
            f"warning: {path} at {version} fails {requirement}, lock has {lock_version}",
            file=sys.stderr,
        )
        return path, False

    checkout(nimbus / path, url, locked["vcsRevision"])
    changes.append(f"{path}: {version} -> {lock_version} ({requirement})")
    return path, True


def align(nimbus, libp2p, checker):
    packages = json.loads((libp2p / "nix/libp2p.lock").read_text())["packages"]
    submodules = vendor_submodules(nimbus)
    changes = []
    pending = checker.read_requirements(libp2p / "libp2p.nimble")
    visited = set()

    while pending:
        requirement = pending.pop(0)
        if checker.package_name(requirement) == "nim":
            continue

        path, moved = align_requirement(
            nimbus, checker, packages, submodules, requirement, changes
        )
        if path is None or (path in visited and not moved):
            continue

        visited.add(path)
        pending.extend(nimble_requirements(checker, nimbus / path))

    return changes


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    nimbus = Path(sys.argv[1]).resolve()
    changes = align(nimbus, nimbus / "vendor/nim-libp2p", load_lock_checker())

    for change in changes:
        print(f"- {change}")
    if not changes:
        print("nimbus-eth2 vendor already satisfies libp2p.nimble")
    return 0


if __name__ == "__main__":
    sys.exit(main())
