import joblib
import pandas as pd

model = joblib.load("intrusion_app/ml/model.pkl")

def predict_packet(features):
    df = pd.DataFrame([features])
    result = model.predict(df)[0]

    if result == 1:
        return "ATTACK"
    return "NORMAL"
