import json
import os

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "detection_benchmark.json",
)

with open(FIXTURE_PATH, "r") as f:
    _data = json.load(f)

cases = _data["cases"]


def load_benchmark_cases():
    """Load the 50 benchmark cases."""
    return cases