import joblib
import numpy as np
from pathlib import Path

# Load artifacts from the package directory (this file's folder)
base = Path(__file__).resolve().parent
model_path = base / 'model.pkl'
scaler_path = base / 'scaler.pkl'
encoder_path = base / 'encoder.pkl'

missing = [p.name for p in (model_path, scaler_path, encoder_path) if not p.exists()]
if missing:
    raise FileNotFoundError(
        f"Missing model artifacts in {base!s}: {missing}.\n"
        "Generate them by running intrusion_app/ai/train_model.py from the ai folder, "
        "or place the files there with these names: model.pkl, scaler.pkl, encoder.pkl"
    )

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)
encoder = joblib.load(encoder_path)

def predict_intrusion(data):
    """
    data = dict with network values
    """
    protocol_encoded = encoder.transform([data['protocol']])[0]

    features = np.array([[
        data['duration'],
        data['src_bytes'],
        data['dst_bytes'],
        data['count'],
        data['srv_count'],
        protocol_encoded
    ]])

    features_scaled = scaler.transform(features)
    result = model.predict(features_scaled)[0]

    return "ATTACK " if result == 1 else "NORMAL "
