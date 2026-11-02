#!/usr/bin/env python3
"""Run upstream Shadow scenarios with a guaranteed mix of implementations."""

import argparse
import json
import os
import random
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-plans", type=Path, required=True)
    parser.add_argument("--nim-peer", type=Path, required=True)
    parser.add_argument("--composition", nargs="+", required=True)
    parser.add_argument(
        "--scenario", choices=["waggle", "waggle-sparse"], default="waggle"
    )
    parser.add_argument("--node-count", type=int, default=8)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    harness = args.test_plans.resolve() / "waggle-interop"
    nim_peer = args.nim_peer.resolve()
    output = args.output_dir.resolve()
    if args.node_count < len(args.composition):
        parser.error("node-count must include every requested implementation")
    if output.exists():
        parser.error(f"output directory already exists: {output}")
    sys.path.insert(0, str(harness))
    import experiment
    from network_graph import generate_graph

    experiment.IMPLEMENTATIONS["nim"] = str(nim_peer)
    experiment.composition(args.composition)  # Validate implementation names.
    random.seed(args.seed)
    params = experiment.scenario(args.scenario, args.node_count)
    # Balance the actual host assignment; upstream uses random.choices, which
    # can omit implementations entirely in small simulations.
    implementations = [
        args.composition[i % len(args.composition)] for i in range(args.node_count)
    ]
    random.shuffle(implementations)
    binaries = [
        str((harness / experiment.IMPLEMENTATIONS[name]).resolve())
        for name in implementations
    ]
    for binary in set(binaries):
        if not os.access(binary, os.X_OK):
            parser.error(f"build the peer first: {binary}")

    output.parent.mkdir(parents=True, exist_ok=True)
    os.chdir(harness)
    params_path = harness / "params.json"
    data = asdict(params)
    data["script"] = [
        instruction.model_dump(exclude_none=True) for instruction in params.script
    ]
    params_path.write_text(json.dumps(data))
    generate_graph(binaries, "graph.gml", "shadow.yaml", str(params_path))
    subprocess.run(
        ["shadow", "--progress", "false", "-d", str(output), "shadow.yaml"], check=True
    )
    for name in ["params.json", "graph.gml", "shadow.yaml"]:
        (output / name).write_bytes((harness / name).read_bytes())
    (output / "implementations.json").write_text(
        json.dumps(dict(enumerate(implementations)), indent=2)
    )

    logs = list((output / "hosts").glob("node*/*.stdout"))
    if len(logs) != args.node_count:
        raise RuntimeError(f"Expected {args.node_count} stdout logs, got {len(logs)}")
    # Check the actual object IDs, not just a substring or a process exit code.
    object_ids = {
        str(instruction.instruction.objectID)
        for instruction in params.script
        if instruction.type == "ifNodeIDEquals"
        and instruction.instruction.type == "addPiece"
    }
    if not object_ids:
        raise RuntimeError("Scenario did not seed any objects")
    for log in logs:
        events = [json.loads(line) for line in log.read_text().splitlines()]
        completed = {
            str(event["object_id"])
            for event in events
            if event.get("msg") == "All parts received"
        }
        if not object_ids <= completed:
            raise RuntimeError(
                f"{log}: missing reconstructed objects {object_ids - completed}"
            )
    print(
        f"PASS: {args.scenario}, {'/'.join(args.composition)}, {len(logs)} nodes reconstructed {object_ids}"
    )


if __name__ == "__main__":
    main()
