import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib

# 1. Load dataset (workspace-relative path)
data_file = Path(__file__).resolve().parents[1] / 'dataSets' / '1.csv'
if not data_file.exists():
    raise FileNotFoundError(f"Dataset not found at {data_file!s}. Make sure 'dataSets/1.csv' exists relative to the project root.")
data = pd.read_csv(data_file)

# 2. Verify required columns exist and encode categorical columns if present
required = ['protocol_type', 'service', 'flag', 'label']
missing = [c for c in required if c not in data.columns]
if missing:
    raise KeyError(
        f"Missing expected columns: {missing}.\n"
        f"Dataset columns: {list(data.columns)}\n"
        "Update `train_model.py` to use the correct column names for your dataset, "
        "or provide a dataset that includes these columns."
    )

label_enc = LabelEncoder()
for col in ['protocol_type', 'service', 'flag']:
    if col in data.columns:
        data[col] = label_enc.fit_transform(data[col])

# 3. Select features and labels
X = data.drop(['label'], axis=1)
y = data['label']

# Convert labels: normal = 0, attack = 1
y = y.apply(lambda x: 0 if x == 'normal' else 1)

# 4. Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Normalize data
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# 6. Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 7. Evaluate
accuracy = model.score(X_test, y_test)
print("Model Accuracy:", accuracy)

# 8. Save model and scaler
joblib.dump(model, 'ids_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
