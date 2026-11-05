#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

"""Run the prebuilt Nim and Rust Waggle peers with bounded waits and cleanup."""

import pathlib
import subprocess
import tempfile
import time


def run(scenario):
    root = pathlib.Path(__file__).resolve().parent
    rust = root / "rust-peer/target/debug/waggle-interop-peer"
    nim = root / "nim-peer/src/peer"
    with tempfile.TemporaryDirectory(prefix="waggle-interop-") as temp:
        address = pathlib.Path(temp) / "peer.addr"
        log_path = pathlib.Path(temp) / "rust.log"
        with log_path.open("w+") as log:
            args = [scenario] if scenario else []
            peer = subprocess.Popen([str(rust), str(address), *args], stdout=log, stderr=log)
            clients = []
            try:
                deadline = time.monotonic() + 20
                while not address.exists() or not address.read_text():
                    if peer.poll() is not None:
                        raise RuntimeError("Rust peer exited before listening")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Rust peer did not start within 20 seconds")
                    time.sleep(0.05)
                roles = [["1"], ["4"]] if scenario == "topology" else [[]]
                for role in roles:
                    clients.append(subprocess.Popen([str(nim), address.read_text().strip(), *args, *role]))
                deadline = time.monotonic() + 65
                for client in clients:
                    if client.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
                        raise RuntimeError("Nim peer failed its assertions")
                if peer.wait(timeout=10) != 0:
                    raise RuntimeError("Rust peer failed its assertions")
                print(f"Waggle Nim/Rust {scenario or 'wire'} interoperability passed", flush=True)
            finally:
                for client in clients:
                    if client.poll() is None:
                        client.terminate()
                        try:
                            client.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            client.kill()
                            client.wait()
                if peer.poll() is None:
                    peer.terminate()
                    try:
                        peer.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        peer.kill()
                        peer.wait()
                log.seek(0)
                print(log.read(), end="", flush=True)


if __name__ == "__main__":
    run(None)
    run("reconcile")
    run("topology")
    run("lifecycle")
    run("pressure")
