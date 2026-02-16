import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# 1️⃣ Load dataset
data = pd.read_csv("dataset.csv")

# 2️⃣ Convert protocol to numbers
encoder = LabelEncoder()
data['protocol'] = encoder.fit_transform(data['protocol'])

# 3️⃣ Convert attack labels
data['attack'] = data['attack'].map({'normal': 0, 'attack': 1})

# 4️⃣ Split features & labels
X = data.drop('attack', axis=1)
y = data['attack']

# 5️⃣ Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 6️⃣ Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

# 7️⃣ Train model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# 8️⃣ Accuracy
accuracy = model.score(X_test, y_test)
print("Model Accuracy:", accuracy)

# 9️⃣ Save model
joblib.dump(model, "model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(encoder, "encoder.pkl")

print(" Model trained & saved successfully")
