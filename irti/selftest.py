#!/usr/bin/env python3
"""High-value checks: the failures most likely to silently corrupt results.

Run:  python3 selftest.py
"""

import ast
import json
import os
import tempfile
import unittest

import degrade
import genlog
import reconstruct
from score import score_recon
from vectors import all_vectors

HERE = os.path.dirname(os.path.abspath(__file__))
RECON_PATH = os.path.join(HERE, "reconstruct.py")


def _lines(p):
    with open(p) as f:
        return [ln for ln in f.read().splitlines() if ln.strip()]


def _read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


def _read_text(p):
    with open(p) as f:
        return f.read()


class TestDeterminism(unittest.TestCase):
    def test_same_seed_byte_identical(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            for vec in sorted(all_vectors()):
                p1, g1, _ = genlog.generate(3, 300, vec, d1)
                p2, g2, _ = genlog.generate(3, 300, vec, d2)
                self.assertEqual(_read_bytes(p1), _read_bytes(p2), vec)
                self.assertEqual(_read_bytes(g1), _read_bytes(g2), vec)


class TestGeneratedLog(unittest.TestCase):
    def test_structure_and_ground_truth(self):
        with tempfile.TemporaryDirectory() as d:
            for vec in sorted(all_vectors()):
                log, gt_path, gt = genlog.generate(0, 400, vec, d)
                lines = _lines(log)
                self.assertEqual(gt["n"], len(lines))
                self.assertEqual(len(gt["attack_events"]), len(set(gt["attack_events"])))
                ids = set(range(len(lines)))
                self.assertTrue(set(gt["attack_events"]) <= ids)

                times = {}
                for ln in lines:
                    parts = [q.strip() for q in ln.split("|")]
                    self.assertEqual(len(parts), 8)
                    times[int(parts[0])] = (parts[2], parts[1])
                for a, b, _t in gt["links"]:
                    self.assertIn(a, times)
                    self.assertIn(b, times)
                    self.assertLess(times[a][1], times[b][1], "link goes backwards")

                # attack is embedded in benign noise, not a contiguous block
                span = max(gt["attack_events"]) - min(gt["attack_events"]) + 1
                self.assertGreater(span, len(gt["attack_events"]), vec)
                self.assertGreater(min(gt["attack_events"]), 5, vec)
                self.assertGreater(len(lines) - max(gt["attack_events"]), 5, vec)

    def test_full_evidence_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            for vec in sorted(all_vectors()):
                log, gt_path, gt = genlog.generate(1, 400, vec, d)
                recon = reconstruct.reconstruct(log)
                r = score_recon(recon, gt)
                self.assertGreaterEqual(r["recall"], 0.99, "%s recall" % vec)
                self.assertTrue(r["decision_correct"], "%s decision" % vec)


class TestDegradation(unittest.TestCase):
    def test_source_removal(self):
        with tempfile.TemporaryDirectory() as d:
            log, _gt, gt = genlog.generate(0, 300, "phishing_powershell", d)
            out = os.path.join(d, "runs", "no_process.log")
            total, kept = degrade.degrade(log, out, "no_process")
            self.assertEqual(total, len(_lines(log)))
            srcs = {ln.split("|")[2].strip() for ln in _lines(out)}
            self.assertNotIn("process", srcs)
            self.assertEqual(kept, len(_lines(out)))

    def test_random_loss_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            log, _gt, gt = genlog.generate(0, 1000, "phishing_powershell", d)
            out = os.path.join(d, "random_50.log")
            total, kept = degrade.degrade(log, out, "random_50", seed=7)
            self.assertGreater(kept, total * 0.40)
            self.assertLess(kept, total * 0.60)

    def test_combined_degradation(self):
        with tempfile.TemporaryDirectory() as d:
            log, _gt, gt = genlog.generate(0, 300, "phishing_powershell", d)
            out = os.path.join(d, "combined.log")
            total, kept = degrade.degrade(log, out, "no_process+no_dns")
            srcs = {ln.split("|")[2].strip() for ln in _lines(out)}
            self.assertNotIn("process", srcs)
            self.assertNotIn("dns", srcs)
            self.assertGreater(kept, 0)


class TestStageRecall(unittest.TestCase):
    def test_full_evidence_stage_recall(self):
        with tempfile.TemporaryDirectory() as d:
            for vec in sorted(all_vectors()):
                log, gt_path, gt = genlog.generate(1, 400, vec, d)
                recon = reconstruct.reconstruct(log)
                r = score_recon(recon, gt)
                self.assertGreaterEqual(r["stage_recall"], 0.8,
                                        "%s stage_recall" % vec)


class TestNoGroundTruthLeakage(unittest.TestCase):
    def test_reconstruct_imports_nothing_from_generator(self):
        tree = ast.parse(_read_text(RECON_PATH))
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module.split(".")[0])
        forbidden = {"genlog", "benign", "vectors", "score", "degrade", "run"}
        self.assertEqual(mods & forbidden, set(), "reconstruct.py must be generator-blind")

    def test_reconstruct_reads_only_its_logfile(self):
        src = _read_text(RECON_PATH)
        self.assertNotIn("ground_truth", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
