import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Fake but realistic dataset
data = pd.DataFrame({
    "packet_size": [60, 1500, 300, 1200, 80, 1400],
    "protocol": [1, 1, 2, 1, 2, 1],
    "src_port": [1234, 80, 53, 22, 443, 8080],
    "dst_port": [80, 8080, 5353, 22, 443, 80],
    "label": [0, 1, 0, 1, 0, 1]
})

X = data.drop("label", axis=1)
y = data["label"]

model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, "model.pkl")
print("Model trained")

