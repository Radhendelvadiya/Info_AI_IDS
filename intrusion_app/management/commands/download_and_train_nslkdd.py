from django.core.management.base import BaseCommand
from pathlib import Path
import requests
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib


NSL_TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
NSL_TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

# Column names for NSL-KDD (41 features + label)
COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
    'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
    'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','label'
]


class Command(BaseCommand):
    help = 'Download NSL-KDD train/test, preprocess, train model, save metrics'

    def handle(self, *args, **options):
        base = Path(__file__).resolve().parents[3]
        data_dir = base / 'intrusion_app' / 'ai' / 'nslkdd'
        data_dir.mkdir(parents=True, exist_ok=True)

        train_path = data_dir / 'KDDTrain+.txt'
        test_path = data_dir / 'KDDTest+.txt'

        self.stdout.write('Downloading NSL-KDD train/test...')
        for url, path in ((NSL_TRAIN_URL, train_path), (NSL_TEST_URL, test_path)):
            try:
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                path.write_bytes(r.content)
                self.stdout.write(f'Downloaded {path.name}')
            except Exception as e:
                self.stderr.write(f'Failed to download {url}: {e}')
                return

        # Load datasets
        self.stdout.write('Loading datasets into pandas...')
        try:
            df_train = pd.read_csv(train_path, names=COLS)
            df_test = pd.read_csv(test_path, names=COLS)
        except Exception as e:
            self.stderr.write('Failed to read downloaded files: %s' % e)
            return

        # Normalize label to binary: normal -> 0, others -> 1
        df_train['attack'] = df_train['label'].apply(lambda x: 0 if 'normal' in str(x).lower() else 1)
        df_test['attack'] = df_test['label'].apply(lambda x: 0 if 'normal' in str(x).lower() else 1)

        # Drop original label
        df_train = df_train.drop(columns=['label'])
        df_test = df_test.drop(columns=['label'])

        # Identify categorical cols
        cat_cols = df_train.select_dtypes(include=['object']).columns.tolist()
        encoders = {}
        for col in cat_cols:
            le = LabelEncoder()
            # fit on combined values to avoid unseen labels
            values = pd.concat([df_train[col].astype(str), df_test[col].astype(str)])
            le.fit(values)
            df_train[col] = le.transform(df_train[col].astype(str))
            df_test[col] = le.transform(df_test[col].astype(str))
            encoders[col] = le

        X_train = df_train.drop(columns=['attack'])
        y_train = df_train['attack']
        X_test = df_test.drop(columns=['attack'])
        y_test = df_test['attack']

        scaler = StandardScaler()
        Xs_train = scaler.fit_transform(X_train)
        Xs_test = scaler.transform(X_test)

        self.stdout.write('Training RandomForest on NSL-KDD...')
        model = RandomForestClassifier(n_estimators=200, n_jobs=-1)
        model.fit(Xs_train, y_train)

        acc = model.score(Xs_test, y_test)
        self.stdout.write(f'NSL-KDD test accuracy: {acc:.4f}')

        # Save artifacts
        ml_dir = base / 'intrusion_app' / 'ml'
        ml_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, ml_dir / 'model.pkl')
        joblib.dump(scaler, ml_dir / 'scaler.pkl')
        joblib.dump(encoders, ml_dir / 'encoders_nslkdd.pkl')

        # Record metric in DB
        try:
            from intrusion_app.models import ModelMetric
            ModelMetric.objects.create(accuracy=acc)
        except Exception:
            pass

        self.stdout.write('Model and artifacts saved in intrusion_app/ml/')