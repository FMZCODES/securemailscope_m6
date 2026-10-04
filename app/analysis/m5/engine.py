from .feature_extractor import extract_features
from .predictor import predict_risk
from .risk_engine import calculate_risk


def analyze(m4_result):
    results = []

    for stream in m4_result.get("results", []):
        features = extract_features(stream)
        ml_risk, model_status = predict_risk(features)
        risk = calculate_risk(features, ml_risk=ml_risk)

        results.append({
            "stream_id": stream.get("stream_id"),
            "protocol": stream.get("protocol"),
            "features": features,
            "risk": risk,
            "ml_model_status": model_status,
            "findings": stream.get("findings", []),
        })

    return {
        "module": "M5 - AI/ML and Risk Engine",
        "streams_analyzed": len(results),
        "results": results,
    }
