#!/usr/bin/env python3
"""Keep the `nimbus-soak` commit status of a nim-libp2p commit on the nimbus.hoodi libp2p nodes.

Usage:
  nimbus_soak.py previous
  nimbus_soak.py start <libp2p sha> [<previous libp2p sha>]
  nimbus_soak.py poll
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlencode

NIMBUS_REPO = "status-im/nimbus-eth2"
FLEET_BRANCH = "nim-libp2p-auto-bump-unstable"
CONTEXT = "nimbus-soak"
PROMETHEUS = "https://metrics.status.im/api/datasources/proxy/uid/P5354BB48EF90EBE5/api/v1"
DASHBOARD = "https://metrics.status.im/d/pgeNfj2Wz23/nimbus-beacon-node?orgId=1&var-fleet=nimbus.hoodi"
NODES = 'fleet="nimbus.hoodi",container=~"beacon-node-hoodi-libp2p-.*"'
HOODI_GENESIS = 1742213400
SLOT_SECONDS = 12
SOAK_SECONDS = 48 * 3600
DEPLOY_DEADLINE_SECONDS = 30 * 3600
# Each node rebuilds and restarts daily at its own hour; the build takes up to about 15 minutes.
UPDATE_WINDOW_SECONDS = 30 * 60
STALE_SECONDS = 15 * 60
STEP_SECONDS = 60
WAITING = "waiting for the hoodi libp2p nodes to deploy this commit"
MAX_SYNC_DISTANCE = 32
MIN_PEERS = 30


def gh(*args):
    return subprocess.run(
        ["gh", "api", *args], check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def node_name(container):
    return container.removeprefix("beacon-node-hoodi-")


def in_update_window(t, update_hour):
    return t // 3600 % 24 == update_hour and t % 3600 < UPDATE_WINDOW_SECONDS


def fleet_head():
    commit = json.loads(gh(f"repos/{NIMBUS_REPO}/commits/heads/{FLEET_BRANCH}"))
    m = re.match(r"test nim-libp2p ([0-9a-f]{40})", commit["commit"]["message"])
    return commit["sha"], m[1] if m else None


def soak_status(sha):
    statuses = json.loads(gh(f"repos/{os.environ['GITHUB_REPOSITORY']}/commits/{sha}/status"))["statuses"]
    return next((s for s in statuses if s["context"] == CONTEXT), None)


def set_status(sha, state, description, since=None):
    url = DASHBOARD + (f"&from={since * 1000}&to=now" if since else "")
    gh(
        f"repos/{os.environ['GITHUB_REPOSITORY']}/statuses/{sha}",
        "-f", f"state={state}",
        "-f", f"context={CONTEXT}",
        "-f", f"description={description[:140]}",
        "-f", f"target_url={url}",
    )
    print(f"{sha[:10]} {state}: {description}")


def prometheus(path, **params):
    with urllib.request.urlopen(f"{PROMETHEUS}/{path}?{urlencode(params)}", timeout=60) as reply:
        body = json.load(reply)
    if body["status"] != "success":
        raise SystemExit(f"prometheus {path} failed: {body}")
    return body["data"]["result"]


def node_versions():
    result = prometheus("query", query=f"version{{{NODES}}}")
    return {r["metric"]["container"]: r["metric"].get("commit", "") for r in result}


def update_hours(before):
    week = node_series(f"process_start_time_seconds{{{NODES}}}", before - 7 * 86400, before, step=300)
    return {
        container: Counter(int(v) // 3600 % 24 for v in {v for _, v in points}).most_common(1)[0][0]
        for container, points in week.items()
    }


def node_series(query, start, end, step=STEP_SECONDS):
    result = prometheus("query_range", query=query, start=start, end=end, step=step)
    return {r["metric"]["container"]: [(int(t), float(v)) for t, v in r["values"]] for r in result}


def print_previous():
    try:
        _, libp2p_sha = fleet_head()
    except subprocess.CalledProcessError:
        return
    if libp2p_sha:
        print(libp2p_sha)


def start(sha, previous=None):
    if previous and previous != sha:
        status = soak_status(previous)
        if status and status["state"] == "pending":
            set_status(previous, "failure", f"superseded on the hoodi fleet by nim-libp2p {sha[:10]}")
    set_status(sha, "pending", WAITING)


def wait_for_deploy(libp2p_sha, nimbus_sha, status, now):
    if version_problem(nimbus_sha) is None:
        starts = prometheus("query", query=f"process_start_time_seconds{{{NODES}}}")
        since = int(max(float(r["value"][1]) for r in starts))
        return "pending", f"deployed at {iso(since)}, soaking for 48h", since

    if now - parse_iso(status["created_at"]) > DEPLOY_DEADLINE_SECONDS:
        return "failure", f"the hoodi libp2p nodes did not deploy nimbus-eth2 {nimbus_sha[:6]} within 30h"

    print(f"{libp2p_sha[:10]}: waiting for the hoodi libp2p nodes to run nimbus-eth2 {nimbus_sha[:6]}")
    return None


def version_problem(nimbus_sha):
    versions = node_versions()
    if not versions:
        return "no hoodi libp2p node reports metrics"
    for container, commit in versions.items():
        if not commit or not nimbus_sha.startswith(commit):
            return f"{node_name(container)} runs nimbus-eth2 {commit or '?'}, not {nimbus_sha[:6]}"
    return None


def restart_problem(hours, since, now):
    for container, points in node_series(f"process_start_time_seconds{{{NODES}}}", since, now).items():
        for t in sorted({int(v) for _, v in points}):
            if t > since and not in_update_window(t, hours.get(container)):
                return f"{node_name(container)} restarted at {iso(t)}"
    return None


def stale_problem(hours, since, now):
    up = node_series(f"up{{{NODES}}}", since, now)
    for container in node_versions().keys() | up.keys():
        last = up[container][-1][0] if container in up else since
        if last < now - STALE_SECONDS and not in_update_window(now, hours.get(container)):
            return f"no metrics from {node_name(container)} since {iso(last)}"
    return None


def health_problem(hours, since, now):
    checks = [
        (f"up{{{NODES}}}", lambda v: v == 0, "was down"),
        (f"libp2p_peers{{{NODES}}}", lambda v: v < MIN_PEERS, f"had under {MIN_PEERS} peers"),
        (
            f"(time() - {HOODI_GENESIS}) / {SLOT_SECONDS} - beacon_head_slot{{{NODES}}}",
            lambda v: v > MAX_SYNC_DISTANCE,
            f"was over {MAX_SYNC_DISTANCE} slots behind the head",
        ),
    ]
    for query, unhealthy, what in checks:
        for container, points in node_series(query, since, now).items():
            update_hour = hours.get(container)
            bad = next((t for t, v in points if not in_update_window(t, update_hour) and unhealthy(v)), None)
            if bad is not None:
                return f"{node_name(container)} {what} at {iso(bad)}"
    return None


def check_soak(libp2p_sha, nimbus_sha, since, now):
    hours = update_hours(since)
    problem = (
        version_problem(nimbus_sha)
        or restart_problem(hours, since, now)
        or stale_problem(hours, since, now)
        or health_problem(hours, since, now)
    )
    if problem:
        return "failure", problem, since

    if now - since >= SOAK_SECONDS:
        return "success", f"healthy on the hoodi libp2p nodes for 48h since {iso(since)}", since

    print(f"{libp2p_sha[:10]}: healthy for {(now - since) // 3600}h since {iso(since)}")
    return None


def poll():
    nimbus_sha, libp2p_sha = fleet_head()
    if libp2p_sha is None:
        print(f"{NIMBUS_REPO} {FLEET_BRANCH} head {nimbus_sha[:10]} is not a nim-libp2p test commit")
        return

    status = soak_status(libp2p_sha)
    if status is None:
        set_status(libp2p_sha, "pending", WAITING)
        return

    if status["state"] != "pending":
        print(f"{libp2p_sha[:10]}: no pending soak")
        return

    now = int(time.time())
    m = re.match(r"deployed at (\S+),", status["description"] or "")
    if m:
        verdict = check_soak(libp2p_sha, nimbus_sha, parse_iso(m[1]), now)
    else:
        verdict = wait_for_deploy(libp2p_sha, nimbus_sha, status, now)
    if verdict is None:
        return

    # A fleet push during the slow queries supersedes this commit; start() already wrote its status.
    if fleet_head()[1] != libp2p_sha:
        print(f"{libp2p_sha[:10]}: superseded on {FLEET_BRANCH} during the poll")
        return

    set_status(libp2p_sha, *verdict)


def main(args):
    if args[:1] == ["poll"] and len(args) == 1:
        poll()
    elif args[:1] == ["previous"] and len(args) == 1:
        print_previous()
    elif args[:1] == ["start"] and len(args) in (2, 3):
        start(*args[1:])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
