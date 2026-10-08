#!/usr/bin/env python3
"""Generate the study figures from results/results.csv.

Figures (written to results/figures/):
    resilience_source_removal.png  F1 + decision correctness vs evidence
                                   retained, one panel per attack vector
    resilience_random_loss.png     F1 + decision correctness vs % of records
                                   randomly removed, with resilience thresholds
    source_importance.png          degradation caused by removing each source
    confidence_calibration.png     reported confidence vs actual F1

Requires matplotlib (use .venv/bin/python, see README).
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib is required for plots: run with .venv/bin/python plots.py")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

F1_COLOR = "#1f77b4"
DEC_COLOR = "#d95f02"
F1_BAR = 0.80
DEC_BAR = 0.90

SOURCE_LABELS = {
    "no_process": "process",
    "no_network": "network+DNS",
    "no_dns": "DNS",
    "no_file": "file",
    "no_logon": "logon",
}

VECTOR_LABELS = {
    "phishing_powershell": "Phishing \u2192 PowerShell",
    "exploit_webshell": "Web exploit \u2192 webshell",
    "credential_dumping": "Credential theft \u2192 lateral",
}


def vector_label(v):
    return VECTOR_LABELS.get(v, v)


def load(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k in ("evidence_pct", "precision", "recall", "f1", "confidence"):
            r[k] = float(r[k])
        for k in ("tp", "fp", "fn", "n_total", "n_kept", "decision_correct", "seed"):
            r[k] = int(r[k])
    return rows


def _std(xs):
    if len(xs) < 2:
        return 0.0
    m = sum(xs) / len(xs)
    return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5


def stats(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["vector"], r["condition"])].append(r)
    out = {}
    for key, rs in groups.items():
        n = len(rs)
        out[key] = {
            "n": n,
            "ev": sum(r["evidence_pct"] for r in rs) / n,
            "f1": sum(r["f1"] for r in rs) / n,
            "f1_std": _std([r["f1"] for r in rs]),
            "dec": sum(r["decision_correct"] for r in rs) / n,
            "dec_std": _std([r["decision_correct"] for r in rs]),
        }
    return out


def _vectors_with(st, conditions):
    return sorted({v for (v, c) in st if c in conditions})


def _style(ax, title, xlabel, ylabel):
    ax.set_title(title, fontsize=11)
    ax.set_xlabel(xlabel, fontsize=9)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.set_ylim(-0.05, 1.08)
    ax.grid(True, alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(labelsize=8)


def _threshold(pts, bar):
    """First x (ascending) where the curve crosses below `bar`, interpolated."""
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if y0 >= bar > y1:
            return x0 + (y0 - bar) / (y0 - y1) * (x1 - x0)
    if pts and pts[-1][1] < bar and pts[0][1] < bar:
        return pts[0][0]
    return None


def fig_resilience_source(st, source_conditions, outdir):
    vectors = _vectors_with(st, source_conditions)
    if not vectors:
        return None
    fig, axes = plt.subplots(1, len(vectors), figsize=(5.8 * len(vectors), 4.2),
                             squeeze=False)
    width = 0.38
    for ax, vec in zip(axes[0], vectors):
        cs = [c for c in source_conditions if (vec, c) in st]
        cs.sort(key=lambda c: -st[(vec, c)]["ev"])
        xs = list(range(len(cs)))
        f1 = [st[(vec, c)]["f1"] for c in cs]
        f1e = [st[(vec, c)]["f1_std"] for c in cs]
        dec = [st[(vec, c)]["dec"] for c in cs]
        dece = [st[(vec, c)]["dec_std"] for c in cs]
        ax.bar([x - width / 2 for x in xs], f1, width, yerr=f1e, capsize=3,
               color=F1_COLOR, label="F1")
        ax.bar([x + width / 2 for x in xs], dec, width, yerr=dece, capsize=3,
               color=DEC_COLOR, label="decision correct")
        for x, y in zip(xs, f1):
            ax.annotate("%.2f" % y, (x - width / 2, max(y, 0.0)),
                        textcoords="offset points", xytext=(0, 2),
                        ha="center", fontsize=7, color=F1_COLOR)
        for x, y in zip(xs, dec):
            ax.annotate("%.2f" % y, (x + width / 2, max(y, 0.0)),
                        textcoords="offset points", xytext=(0, 2),
                        ha="center", fontsize=7, color=DEC_COLOR)
        ax.axhline(F1_BAR, ls="--", lw=1, color=F1_COLOR, alpha=0.45)
        ax.axhline(DEC_BAR, ls="--", lw=1, color=DEC_COLOR, alpha=0.45)
        ax.set_xticks(xs)
        ax.set_xticklabels(
            ["%s\n(%.0f%% kept)" % (SOURCE_LABELS.get(c, c), st[(vec, c)]["ev"])
             for c in cs], fontsize=7.5)
        _style(ax, vector_label(vec), "", "score")
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, fontsize=8,
               frameon=False, bbox_to_anchor=(0.5, 0.97))
    fig.suptitle("Resilience under source removal (mean \u00b1 std over seeds)",
                 fontsize=12, y=1.0)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    out = os.path.join(outdir, "resilience_source_removal.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def fig_resilience_random(st, rows, outdir):
    conds = sorted({c for (_v, c) in st if c.startswith("random_")},
                   key=lambda c: int(c.split("_")[1]))
    if not conds:
        return None, {}
    vectors = _vectors_with(st, set(conds) | {"full"})
    fig, axes = plt.subplots(1, len(vectors), figsize=(5.6 * len(vectors), 4.2),
                             squeeze=False)
    thresholds = {}
    for ax, vec in zip(axes[0], vectors):
        xs, f1, f1e, dec, dece = [], [], [], [], []
        if (vec, "full") in st:
            xs.append(0.0)
            f1.append(st[(vec, "full")]["f1"])
            f1e.append(st[(vec, "full")]["f1_std"])
            dec.append(st[(vec, "full")]["dec"])
            dece.append(st[(vec, "full")]["dec_std"])
        for c in conds:
            if (vec, c) not in st:
                continue
            xs.append(float(c.split("_")[1]))
            f1.append(st[(vec, c)]["f1"])
            f1e.append(st[(vec, c)]["f1_std"])
            dec.append(st[(vec, c)]["dec"])
            dece.append(st[(vec, c)]["dec_std"])
        ax.errorbar(xs, f1, yerr=f1e, marker="o", capsize=3, lw=1.6,
                    color=F1_COLOR, label="F1")
        ax.errorbar(xs, dec, yerr=dece, marker="s", capsize=3, lw=1.6,
                    color=DEC_COLOR, label="decision correct")
        ax.axhline(F1_BAR, ls="--", lw=1, color=F1_COLOR, alpha=0.45)
        ax.axhline(DEC_BAR, ls="--", lw=1, color=DEC_COLOR, alpha=0.45)
        t_dec = _threshold(list(zip(xs, dec)), DEC_BAR)
        t_f1 = _threshold(list(zip(xs, f1)), F1_BAR)
        thresholds[vec] = {"f1": t_f1, "dec": t_dec}
        if t_dec is not None:
            ax.axvline(t_dec, ls=":", lw=1.2, color=DEC_COLOR, alpha=0.7)
            ax.annotate("decision threshold\n%.0f%% removed" % t_dec,
                        (t_dec, 0.12), fontsize=7, color=DEC_COLOR,
                        ha="right", va="bottom")
        _style(ax, vector_label(vec), "records randomly removed (%)", "score")
    axes[0][0].legend(fontsize=8, loc="lower left")
    fig.suptitle("Resilience under random record loss (mean \u00b1 std over seeds)",
                 fontsize=12, y=0.99)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    out = os.path.join(outdir, "resilience_random_loss.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out, thresholds


def fig_source_importance(st, source_conditions, outdir):
    order = ["no_process", "no_network", "no_dns", "no_file", "no_logon"]
    vectors = _vectors_with(st, source_conditions)
    if not vectors:
        return None
    fig, axes = plt.subplots(1, len(vectors), figsize=(5.6 * len(vectors), 4.2),
                             squeeze=False)
    width = 0.38
    for ax, vec in zip(axes[0], vectors):
        base = st.get((vec, "full"), {"f1": 1.0, "dec": 1.0})
        cs = [c for c in order if (vec, c) in st]
        xs = list(range(len(cs)))
        df1 = [max(0.0, base["f1"] - st[(vec, c)]["f1"]) for c in cs]
        ddec = [max(0.0, base["dec"] - st[(vec, c)]["dec"]) for c in cs]
        b1 = ax.bar([x - width / 2 for x in xs], df1, width, color=F1_COLOR,
                    label="\u0394 F1")
        b2 = ax.bar([x + width / 2 for x in xs], ddec, width, color=DEC_COLOR,
                    label="\u0394 decision correctness")
        for bars in (b1, b2):
            for rect in bars:
                h = rect.get_height()
                if h > 0.001:
                    ax.annotate("%.2f" % h, (rect.get_x() + rect.get_width() / 2, h),
                                textcoords="offset points", xytext=(0, 2),
                                ha="center", fontsize=7)
        ax.set_xticks(xs)
        ax.set_xticklabels([SOURCE_LABELS.get(c, c) for c in cs], fontsize=8)
        ax.set_title(vector_label(vec), fontsize=11)
        ax.set_ylabel("accuracy drop vs full evidence", fontsize=9)
        ax.set_ylim(0, 1.24)
        ax.grid(True, axis="y", alpha=0.3)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.tick_params(labelsize=8)
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, fontsize=8,
               frameon=False, bbox_to_anchor=(0.5, 0.97))
    fig.suptitle("Source importance: damage from removing one evidence source",
                 fontsize=12, y=1.0)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    out = os.path.join(outdir, "source_importance.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def fig_confidence(rows, outdir):
    vecs = sorted({r["vector"] for r in rows})
    colors = {v: c for v, c in zip(vecs, ["#1f77b4", "#d95f02", "#2ca02c", "#9467bd"])}
    fig, ax = plt.subplots(figsize=(5.4, 4.6))
    for v in vecs:
        rs = [r for r in rows if r["vector"] == v]
        ax.scatter([r["confidence"] for r in rs], [r["f1"] for r in rs],
                   s=26, alpha=0.6, color=colors[v], label=vector_label(v))
    ax.plot([0, 1], [0, 1], ls=":", lw=1, color="gray")
    ax.set_xlim(-0.03, 1.03)
    ax.set_ylim(-0.05, 1.08)
    ax.set_xlabel("engine confidence", fontsize=9)
    ax.set_ylabel("actual F1", fontsize=9)
    ax.set_title("Confidence calibration (all runs)", fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(fontsize=8, loc="lower right")
    fig.tight_layout()
    out = os.path.join(outdir, "confidence_calibration.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", default=os.path.join(BASE_DIR, "results", "results.csv"))
    ap.add_argument("--outdir", default=os.path.join(BASE_DIR, "results", "figures"))
    args = ap.parse_args()

    rows = load(args.results)
    if not rows:
        sys.exit("no rows in %s" % args.results)
    st = stats(rows)
    os.makedirs(args.outdir, exist_ok=True)

    saved = []
    source_conditions = [c for c in SOURCE_LABELS if any((v, c) in st for v, _ in st)]
    p = fig_resilience_source(st, source_conditions, args.outdir)
    if p:
        saved.append(p)
    p, thr = fig_resilience_random(st, rows, args.outdir)
    if p:
        saved.append(p)
    p = fig_source_importance(st, source_conditions, args.outdir)
    if p:
        saved.append(p)
    saved.append(fig_confidence(rows, args.outdir))

    for p in saved:
        print("wrote %s" % os.path.relpath(p, BASE_DIR))
    for vec, t in sorted(thr.items()):
        print("%s: F1<%.2f at %s removed; decision<%.2f at %s removed"
              % (vec,
                 F1_BAR, "%.0f%%" % t["f1"] if t["f1"] is not None else "never",
                 DEC_BAR, "%.0f%%" % t["dec"] if t["dec"] is not None else "never"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
