"""ScamShield Detection Benchmark Runner.

Loads 50 synthetic benchmark cases, runs each through the existing
ScamShield detection pipeline, and generates detailed metrics reports.

No production scoring logic is modified. RiskScorer remains authoritative.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.scam_detector import ScamDetector
from app.services.risk_scoring import RiskScorer


FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "detection_benchmark.json",
)

REPORT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports",
)

RISK_BANDS = ["low", "medium", "high", "critical"]

CLASSIFICATION_THRESHOLD = 25.0


def load_benchmark_cases() -> List[Dict[str, Any]]:
    with open(FIXTURE_PATH, "r") as f:
        data = json.load(f)
    return data["cases"]


def classify_risk_score(score: float) -> str:
    if score >= CLASSIFICATION_THRESHOLD:
        return "scam"
    return "legitimate"


def risk_band_for_score(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def run_case(case: Dict[str, Any], detector: ScamDetector, scorer: RiskScorer) -> Dict[str, Any]:
    message = case["message"]
    signals = detector.detect(message)

    signal_dicts = [
        {"score": s.score, "weight": s.weight}
        for s in signals
    ]
    scoring_result = scorer.score(signal_dicts)

    risk_score = scoring_result["risk_score"]
    risk_band = scoring_result["risk_band"]
    predicted_classification = classify_risk_score(risk_score)

    expected_classification = case["expected_classification"]
    expected_band = case["expected_risk_band"]

    correct_classification = predicted_classification == expected_classification
    correct_band = risk_band == expected_band

    actual_signal_names = [s.name for s in signals]
    actual_categories = [
        (s.metadata or {}).get("category", "unknown")
        for s in signals
        if s.metadata
    ]

    expected_indicators = set(case.get("expected_indicators", []))
    detected_indicators = set()
    for s in signals:
        meta = s.metadata or {}
        cat = meta.get("category", "")
        pattern = meta.get("pattern", "")
        name = s.name
        if cat:
            detected_indicators.add(cat)
        if pattern:
            detected_indicators.add(pattern)
        if name:
            detected_indicators.add(name)

    indicators_correctly_detected = expected_indicators & detected_indicators
    indicators_missed = expected_indicators - detected_indicators

    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "message": message,
        "expected_classification": expected_classification,
        "expected_risk_band": expected_band,
        "predicted_classification": predicted_classification,
        "predicted_risk_band": risk_band,
        "risk_score": risk_score,
        "correct_classification": correct_classification,
        "correct_band": correct_band,
        "actual_signal_names": actual_signal_names,
        "actual_categories": actual_categories,
        "expected_indicators": list(expected_indicators),
        "indicators_correctly_detected": list(indicators_correctly_detected),
        "indicators_missed": list(indicators_missed),
        "num_signals": len(signals),
        "explanation": case.get("explanation", ""),
    }


def calculate_classification_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for r in results:
        expected = r["expected_classification"]
        predicted = r["predicted_classification"]
        if expected == "scam" and predicted == "scam":
            tp += 1
        elif expected == "legitimate" and predicted == "legitimate":
            tn += 1
        elif expected == "legitimate" and predicted == "scam":
            fp += 1
        elif expected == "scam" and predicted == "legitimate":
            fn += 1

    total = len(results)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "total": total,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }


def calculate_risk_band_confusion_matrix(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    matrix = defaultdict(lambda: defaultdict(int))

    for r in results:
        expected = r["expected_risk_band"]
        predicted = r["predicted_risk_band"]
        matrix[expected][predicted] += 1

    result = {}
    for band in RISK_BANDS:
        result[band] = {}
        for pred_band in RISK_BANDS:
            result[band][pred_band] = matrix.get(band, {}).get(pred_band, 0)

    row_totals = {}
    col_totals = {}
    for band in RISK_BANDS:
        row_totals[band] = sum(result[band].values())
        col_totals[band] = sum(result[b].get(band, 0) for b in RISK_BANDS)

    result["_row_totals"] = row_totals
    result["_col_totals"] = col_totals
    result["_grand_total"] = sum(row_totals.values())

    return result


def calculate_category_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    categories = defaultdict(list)
    for r in results:
        categories[r["category"]].append(r)

    category_metrics = {}
    for cat, cat_results in sorted(categories.items()):
        tp = sum(1 for r in cat_results if r["expected_classification"] == "scam" and r["predicted_classification"] == "scam")
        tn = sum(1 for r in cat_results if r["expected_classification"] == "legitimate" and r["predicted_classification"] == "legitimate")
        fp = sum(1 for r in cat_results if r["expected_classification"] == "legitimate" and r["predicted_classification"] == "scam")
        fn = sum(1 for r in cat_results if r["expected_classification"] == "scam" and r["predicted_classification"] == "legitimate")

        total = len(cat_results)
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        category_metrics[cat] = {
            "total": total,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
        }

    return category_metrics


def calculate_detector_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    detector_stats = defaultdict(lambda: {"expected": 0, "detected": 0, "missed": 0})

    for r in results:
        expected_indicators = set(r["expected_indicators"])
        detected_indicators = set(r["indicators_correctly_detected"])
        missed_indicators = set(r["indicators_missed"])

        for indicator in expected_indicators:
            detector_stats[indicator]["expected"] += 1
            if indicator in detected_indicators:
                detector_stats[indicator]["detected"] += 1
            if indicator in missed_indicators:
                detector_stats[indicator]["missed"] += 1

    return dict(detector_stats)


def generate_report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    classification = calculate_classification_metrics(results)
    band_matrix = calculate_risk_band_confusion_matrix(results)
    category_metrics = calculate_category_metrics(results)
    detector_metrics = calculate_detector_metrics(results)

    false_positives = [r for r in results if r["expected_classification"] == "legitimate" and r["predicted_classification"] == "scam"]
    false_negatives = [r for r in results if r["expected_classification"] == "scam" and r["predicted_classification"] == "legitimate"]
    band_errors = [r for r in results if not r["correct_band"]]

    report = {
        "summary": {
            "total_cases": len(results),
            "classification_metrics": classification,
            "risk_band_confusion_matrix": band_matrix,
        },
        "category_metrics": category_metrics,
        "detector_metrics": detector_metrics,
        "false_positives": [
            {
                "case_id": r["case_id"],
                "category": r["category"],
                "risk_score": r["risk_score"],
                "predicted_band": r["predicted_risk_band"],
                "expected_band": r["expected_risk_band"],
                "explanation": r["explanation"],
            }
            for r in false_positives
        ],
        "false_negatives": [
            {
                "case_id": r["case_id"],
                "category": r["category"],
                "risk_score": r["risk_score"],
                "predicted_band": r["predicted_risk_band"],
                "expected_band": r["expected_risk_band"],
                "explanation": r["explanation"],
            }
            for r in false_negatives
        ],
        "risk_band_errors": [
            {
                "case_id": r["case_id"],
                "category": r["category"],
                "expected_band": r["expected_risk_band"],
                "predicted_band": r["predicted_risk_band"],
                "risk_score": r["risk_score"],
            }
            for r in band_errors
        ],
        "detailed_results": results,
    }

    return report


def write_json_report(report: Dict[str, Any], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print("JSON report written to " + output_path)


def write_markdown_report(report: Dict[str, Any], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    lines = []
    lines.append("# ScamShield Detection Benchmark Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    cm = report["summary"]["classification_metrics"]
    lines.append("- Total cases: " + str(report["summary"]["total_cases"]))
    lines.append("- Accuracy: " + str(cm["accuracy"]))
    lines.append("- Precision: " + str(cm["precision"]))
    lines.append("- Recall: " + str(cm["recall"]))
    lines.append("- F1 Score: " + str(cm["f1_score"]))
    lines.append("- Specificity: " + str(cm["specificity"]))
    lines.append("- False Positive Rate: " + str(cm["false_positive_rate"]))
    lines.append("- False Negative Rate: " + str(cm["false_negative_rate"]))
    lines.append("")
    lines.append("### Confusion Matrix")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append("| True Positives | " + str(cm["true_positives"]) + " |")
    lines.append("| True Negatives | " + str(cm["true_negatives"]) + " |")
    lines.append("| False Positives | " + str(cm["false_positives"]) + " |")
    lines.append("| False Negatives | " + str(cm["false_negatives"]) + " |")
    lines.append("")

    lines.append("## Risk Band Confusion Matrix")
    lines.append("")
    matrix = report["summary"]["risk_band_confusion_matrix"]
    bands = ["low", "medium", "high", "critical"]
    lines.append("| Expected \\ Predicted | " + " | ".join(bands) + " | Total |")
    lines.append("|" + "---|" * (len(bands) + 2))
    for band in bands:
        row = "| " + band + " |"
        for pred in bands:
            row += " " + str(matrix.get(band, {}).get(pred, 0)) + " |"
        row += " " + str(matrix.get("_row_totals", {}).get(band, 0)) + " |"
        lines.append(row)
    lines.append("")

    lines.append("## Category-wise Performance")
    lines.append("")
    lines.append("| Category | Total | Accuracy | Precision | Recall | FP | FN |")
    lines.append("|----------|-------|----------|-----------|--------|----|----|")
    for cat, m in sorted(report["category_metrics"].items()):
        lines.append(
            "| " + cat + " | " + str(m["total"]) + " | " + str(m["accuracy"]) +
            " | " + str(m["precision"]) + " | " + str(m["recall"]) +
            " | " + str(m["false_positives"]) + " | " + str(m["false_negatives"]) + " |"
        )
    lines.append("")

    lines.append("## False Positives (Legitimate flagged as scam)")
    lines.append("")
    if report["false_positives"]:
        for fp in report["false_positives"]:
            lines.append("- **Case " + fp["case_id"] + "** (" + fp["category"] + "): Score " +
                         str(fp["risk_score"]) + ", Band " + fp["predicted_band"] +
                         " (expected " + fp["expected_band"] + ")")
            lines.append("  " + fp["explanation"])
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## False Negatives (Scam flagged as legitimate)")
    lines.append("")
    if report["false_negatives"]:
        for fn in report["false_negatives"]:
            lines.append("- **Case " + fn["case_id"] + "** (" + fn["category"] + "): Score " +
                         str(fn["risk_score"]) + ", Band " + fn["predicted_band"] +
                         " (expected " + fn["expected_band"] + ")")
            lines.append("  " + fn["explanation"])
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Risk Band Errors")
    lines.append("")
    if report["risk_band_errors"]:
        for err in report["risk_band_errors"]:
            lines.append("- **Case " + err["case_id"] + "** (" + err["category"] + "): " +
                         "Expected " + err["expected_band"] + ", Got " +
                         err["predicted_band"] + " (Score: " + str(err["risk_score"]) + ")")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    lines.append("1. Review false positives to adjust detector thresholds or add context rules.")
    lines.append("2. Review false negatives to add missing detection patterns.")
    lines.append("3. RiskScorer remains authoritative - do not artificially inflate scores.")
    lines.append("4. Add regression tests for any production detection changes.")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    print("Markdown report written to " + output_path)


def main() -> int:
    print("ScamShield Detection Benchmark")
    print("=" * 40)

    cases = load_benchmark_cases()
    print("Loaded " + str(len(cases)) + " benchmark cases")

    detector = ScamDetector()
    scorer = RiskScorer()

    results = []
    for i, case in enumerate(cases, 1):
        result = run_case(case, detector, scorer)
        results.append(result)
        status = "PASS" if result["correct_classification"] else "FAIL"
        print(
            "  [{:2d}/{:d}] {} {} ({}) score={} band={} expected={}/{}".format(
                i, len(cases), status, result["case_id"],
                result["category"], result["risk_score"],
                result["predicted_risk_band"],
                result["expected_classification"], result["expected_risk_band"]
            )
        )

    report = generate_report(results)

    json_path = os.path.join(REPORT_DIR, "detection_benchmark.json")
    md_path = os.path.join(REPORT_DIR, "detection_benchmark.md")

    write_json_report(report, json_path)
    write_markdown_report(report, md_path)

    cm = report["summary"]["classification_metrics"]
    print("\n" + "=" * 40)
    print("BENCHMARK SUMMARY")
    print("=" * 40)
    print("Accuracy:  " + str(cm["accuracy"]))
    print("Precision: " + str(cm["precision"]))
    print("Recall:    " + str(cm["recall"]))
    print("F1 Score:  " + str(cm["f1_score"]))
    print("FPR:       " + str(cm["false_positive_rate"]))
    print("FNR:       " + str(cm["false_negative_rate"]))
    print("")
    print("False Positives: " + str(len(report["false_positives"])))
    print("False Negatives: " + str(len(report["false_negatives"])))
    print("")
    print("Reports written to " + REPORT_DIR)

    return 0


if __name__ == "__main__":
    sys.exit(main())
