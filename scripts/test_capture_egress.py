#!/usr/bin/env python3
"""Unit tests for the capture-egress.py evidence guards.

Both guards exist to protect previously captured evidence, which is the
artifact #504 acceptance runs on:

1. ``--window-secs < 300`` must be rejected *before* the window is spent.
   The section 5.4 rule rejects short windows, but doing that only after
   ``time.sleep`` + a second snapshot burns the full (invalid) window and
   still leaves t0/t1 files behind as if they were a measurement attempt.
2. An occupied ``--out-dir`` must be rejected before anything is written.
   The script writes fixed filenames (``gossip-t0.json``, ``t1.json``,
   ``topic-names.json``, ...), so pointing it at an existing evidence
   directory silently overwrites the earlier run.

The tests drive the real ``main()`` with ``snapshot`` and ``time.sleep``
stubbed, so no daemon, token, or blake3 wheel is required: ``blake3`` is
faked via ``sys.modules`` before import because the module exits at
import time when the wheel is absent. Each guard test also asserts the
failing arm never reached ``snapshot`` (nothing was collected) and that
files already present in the directory are byte-identical afterwards.
"""

from __future__ import annotations

import importlib
import json
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("capture-egress.py")


def load_module() -> types.ModuleType:
    """Import capture-egress.py with a stubbed blake3 if the wheel is absent."""
    if "blake3" not in sys.modules:
        class _Hash:
            def __init__(self, data: bytes) -> None:
                self.data = data

            def hexdigest(self) -> str:
                return f"{int.from_bytes(self.data[:8], 'big'):016x}"

        fake = types.ModuleType("blake3")
        fake.blake3 = _Hash
        sys.modules["blake3"] = fake
    spec = importlib.util.spec_from_file_location("capture_egress_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class GuardTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tempfile = tempfile.TemporaryDirectory()
        self.root = Path(self._tempfile.name)
        self.module = load_module()
        self.addCleanup(self._tempfile.cleanup)

    def run_main(self, *argv: str) -> None:
        with mock.patch.object(sys, "argv", [str(SCRIPT), *argv]):
            self.module.main()

    def test_short_window_rejected_before_collection(self) -> None:
        out = self.root / "run01"
        with mock.patch.object(self.module.time, "sleep") as sleep, \
                mock.patch.object(self.module, "snapshot") as snap:
            with self.assertRaises(SystemExit) as ctx:
                self.run_main("--window-secs", "299", "--out-dir", str(out))
        self.assertGreaterEqual(ctx.exception.code, 2)  # argparse error path
        sleep.assert_not_called()
        snap.assert_not_called()
        self.assertFalse(out.exists(), "no directory should be created for a rejected window")

    def test_occupied_out_dir_rejected_without_writes(self) -> None:
        out = self.root / "run01"
        out.mkdir()
        (out / "gossip-t0.json").write_text("PREVIOUS EVIDENCE", encoding="utf-8")
        before = sorted((p.name, p.read_bytes()) for p in out.iterdir())
        with mock.patch.object(self.module, "snapshot") as snap:
            with self.assertRaises(SystemExit) as ctx:
                self.run_main("--window-secs", "300", "--out-dir", str(out))
        self.assertNotEqual(ctx.exception.code, 0)
        snap.assert_not_called()
        after = sorted((p.name, p.read_bytes()) for p in out.iterdir())
        self.assertEqual(before, after, "occupied directory must be left byte-identical")

    def test_empty_existing_out_dir_allowed(self) -> None:
        out = self.root / "run01"
        out.mkdir()
        sample = {
            "gossip": {"participation": _participation(), "pubsub_stages": {"outbound_by_topic": {}}},
            "health": {"peers": 3, "uptime_secs": 1000},
        }
        with mock.patch.object(self.module.time, "sleep"), \
                mock.patch.object(self.module, "snapshot", side_effect=lambda label, out_dir: _fake_snapshot(label, out_dir, sample, 300)) as snap:
            self.run_main("--window-secs", "300", "--out-dir", str(out))
        self.assertEqual(snap.call_count, 2)
        for name in ("gossip-t0.json", "gossip-t1.json", "t0.json", "t1.json", "topic-names.json"):
            self.assertTrue((out / name).exists(), f"{name} missing")

    def test_default_window_is_acceptable(self) -> None:
        # The argparse default (1200) must still pass the same guard.
        out = self.root / "run01"
        sample = {
            "gossip": {"participation": _participation(), "pubsub_stages": {"outbound_by_topic": {}}},
            "health": {"peers": 3, "uptime_secs": 1000},
        }
        with mock.patch.object(self.module.time, "sleep"), \
                mock.patch.object(self.module, "snapshot", side_effect=lambda label, out_dir: _fake_snapshot(label, out_dir, sample, 1200)) as snap:
            self.run_main("--out-dir", str(out))
        self.assertTrue((out / "t1.json").exists())


def _participation() -> dict:
    return {
        "mode": "leaf",
        "reason": "default_leaf",
        "passthrough_refresh_runs": 0,
        "epidemic_forward_bytes": 0,
        "epidemic_forward_msgs": 0,
        "relay_bytes": 0,
        "relay_msgs": 0,
        "unsubscribed_refused_frames": 0,
    }


def _fake_snapshot(label: str, out_dir: Path, sample: dict, window: int) -> dict:
    """Mimic the real ``snapshot``: same files on disk, same return shape."""
    result = json.loads(json.dumps(sample))  # independent deep copy per endpoint
    if label == "t1":
        result["health"]["uptime_secs"] += window
    for name in ("gossip", "transport", "health"):
        (out_dir / f"{name}-{label}.json").write_text("{}", encoding="utf-8")
    result["epoch"] = 0.0
    result["monotonic"] = float(window) if label == "t1" else 0.0
    (out_dir / f"{label}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    unittest.main(verbosity=2)
