from __future__ import annotations

from pathlib import Path
import pickle


FEATURES = [
    "critical_findings",
    "high_findings",
    "medium_findings",
    "weak_tls_version",
    "weak_cipher",
    "no_forward_secrecy",
    "weak_public_key",
    "expired_certificate",
    "invalid_certificate_chain",
    "weak_signature_algorithm",
    "starttls_missing",
]


def _predict_tree(tree, values):
    if tree["type"] == "leaf":
        return tree["label"]

    feature_index = int(tree["feature"])
    if values[feature_index] == 0:
        return _predict_tree(tree["left"], values)
    return _predict_tree(tree["right"], values)


def predict_risk(features, model_path: str | Path | None = None):
    """
    Uses the team's M5 ml_model.pkl when present.

    If the model file is not copied into this integration package,
    fall back to the same rule-based level so the combined pipeline
    remains operational. This fallback is explicitly reported as such.
    """
    if model_path is None:
        model_path = Path(__file__).with_name("ml_model.pkl")
    else:
        model_path = Path(model_path)

    if not model_path.exists():
        return None, "rule_based_fallback"

    with model_path.open("rb") as file:
        model = pickle.load(file)

    values = [int(features.get(feature, 0)) for feature in FEATURES]
    return _predict_tree(model, values), "trained_tree"
