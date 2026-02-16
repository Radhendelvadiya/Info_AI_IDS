from django.core.management.base import BaseCommand
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
from pathlib import Path


class Command(BaseCommand):
    help = 'Train IDS model from intrusion_app/ai/dataset.csv and save metrics'

    def handle(self, *args, **options):
        base = Path(__file__).resolve().parents[3]
        data_path = base / 'intrusion_app' / 'ai' / 'dataset.csv'
        if not data_path.exists():
            self.stderr.write('dataset.csv not found at %s' % str(data_path))
            return

        df = pd.read_csv(data_path)

        # Ensure required columns exist; adapt if dataset differs
        if 'attack' not in df.columns:
            self.stderr.write('dataset missing "attack" column')
            return

        # Encode non-numeric columns
        encoders = {}
        for col in df.select_dtypes(include=['object']).columns:
            if col == 'attack':
                continue
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le

        df['attack'] = df['attack'].map({'normal': 0, 'attack': 1}).fillna(0).astype(int)

        X = df.drop('attack', axis=1)
        y = df['attack']

        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(Xs, y, test_size=0.2, random_state=42)

        model = RandomForestClassifier(n_estimators=100)
        model.fit(X_train, y_train)

        acc = model.score(X_test, y_test)

        ml_dir = base / 'intrusion_app' / 'ml'
        ml_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, ml_dir / 'model.pkl')
        joblib.dump(scaler, ml_dir / 'scaler.pkl')
        joblib.dump(encoders, ml_dir / 'encoders.pkl')

        # Save metric via ORM (avoid circular import at top-level)
        try:
            import django
            from intrusion_app.models import ModelMetric
            ModelMetric.objects.create(accuracy=acc)
        except Exception:
            pass

        self.stdout.write('Model trained. Accuracy: %.4f' % acc)