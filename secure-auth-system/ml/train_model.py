import ast
import json
from pathlib import Path

import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler

import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
from backend import keystroke_features  # noqa: E402

DATA_PATH = BASE_DIR / "data" / "keystrokes.csv"
MODEL_PATH = BASE_DIR / "ml" / "model.pkl"


def load_dataset(csv_path: Path):
    """Load dataset with support for new features column."""
    df = pd.read_csv(csv_path, sep="\t", engine="python", on_bad_lines='skip')
    
    # Check for expected columns (new format includes 'features' column)
    expected_cols = {"user_id", "label", "session_id", "keystrokes"}
    if not expected_cols.issubset(set(map(str, df.columns))):
        raise ValueError(
            "Dataset format invalid: expected TSV with columns 'user_id', 'label', 'session_id', 'keystrokes'.\n"
            "If this file was opened/saved in Excel, it may be mangled. Delete or recreate data/keystrokes.csv."
        )
    
    rows = []
    feature_count = 0
    
    for _, row in df.iterrows():
        try:
            # First try to use the stored features if available
            if 'features' in df.columns and pd.notna(row.get('features')):
                try:
                    # Try JSON parsing first
                    feats = json.loads(row['features'])
                    if isinstance(feats, list) and len(feats) >= 16:
                        feature_count = len(feats)
                        rows.append({"features": feats, "label": int(row["label"]), "user_id": row["user_id"]})
                        continue
                except (json.JSONDecodeError, TypeError):
                    # Fallback to ast.literal_eval
                    try:
                        feats = ast.literal_eval(row['features'])
                        if isinstance(feats, list) and len(feats) >= 16:
                            feature_count = len(feats)
                            rows.append({"features": feats, "label": int(row["label"]), "user_id": row["user_id"]})
                            continue
                    except (ValueError, SyntaxError):
                        pass
            
            # Fallback to extracting from keystrokes
            events_str = row["keystrokes"]
            if pd.isna(events_str) or events_str == '':
                continue
                
            events = ast.literal_eval(events_str) if isinstance(events_str, str) else events_str
            features_map = keystroke_features.extract_features(events)
            feats = keystroke_features.feature_vector(features_map)
            feature_count = len(feats)
            rows.append({"features": feats, "label": int(row["label"]), "user_id": row["user_id"]})
            
        except Exception as e:
            print(f"Warning: Could not process row: {e}")
            continue
    
    if not rows:
        return [], [], 0
    
    X = [r["features"] for r in rows]
    y = [r["label"] for r in rows]
    
    print(f"[train] Loaded {len(X)} samples with {feature_count} features each")
    print(f"[train] Class distribution: {pd.Series(y).value_counts().to_dict()}")
    
    return X, y


def analyze_features(X, y):
    """Analyze feature importance and distributions."""
    from collections import defaultdict
    
    # Convert to numpy
    X_array = np.array(X)
    y_array = np.array(y)
    
    # Separate by class
    legit_indices = np.where(y_array == 1)[0]
    fraud_indices = np.where(y_array == 0)[0]
    
    if len(legit_indices) == 0 or len(fraud_indices) == 0:
        print("[train] Need both classes for feature analysis")
        return
    
    # Feature names (based on keystroke_features.py)
    feature_names = [
        "dwell_mean", "dwell_std", "dwell_median",
        "flight_mean", "flight_std", "flight_median",
        "total_time", "key_count", "cadence",
        "rhythm_consistency", "pressure_variance",
        "dwell_flight_ratio", "dwell_cv",
        "pattern_entropy", "key_variation", "typing_burstiness"
    ]
    
    # Analyze mean differences
    legit_means = np.mean(X_array[legit_indices], axis=0)
    fraud_means = np.mean(X_array[fraud_indices], axis=0)
    
    differences = np.abs(legit_means - fraud_means)
    top_indices = np.argsort(differences)[-5:][::-1]  # Top 5 most different
    
    print("\n=== Feature Analysis ===")
    print("Top 5 most different features between legitimate and fraudulent:")
    for idx in top_indices:
        feat_name = feature_names[idx] if idx < len(feature_names) else f"Feature_{idx}"
        print(f"  {feat_name}: Legit={legit_means[idx]:.4f}, Fraud={fraud_means[idx]:.4f}, Diff={differences[idx]:.4f}")


def main():
    if not DATA_PATH.exists():
        print(f"[train] Dataset not found at {DATA_PATH}")
        print("[train] Create it by registering and logging in users first.")
        return
    
    try:
        X, y = load_dataset(DATA_PATH)
    except ValueError as e:
        print(f"[train] {e}")
        print("[train] To reset the dataset, you can run this in PowerShell:")
        print('Set-Content -Path "data/keystrokes.csv" -Value "user_id`tlabel`tsession_id`tkeystrokes`tfeatures`n"')
        return
    
    if not X or not y or len(X) != len(y):
        print("[train] No usable data found in dataset. Skipping training.")
        print("[train] Need at least some successful (label=1) and failed (label=0) login attempts.")
        return
    
    # Analyze features
    analyze_features(X, y)
    
    # Check class distribution
    n_classes = len(set(y))
    class_counts = pd.Series(y).value_counts()
    
    print(f"\n[train] Dataset stats:")
    print(f"  Total samples: {len(y)}")
    print(f"  Legitimate (1): {class_counts.get(1, 0)}")
    print(f"  Fraudulent (0): {class_counts.get(0, 0)}")
    
    if n_classes < 2:
        print("[train] Need samples from both classes (legitimate and fraudulent) for binary classification.")
        print("[train] Register users and attempt some logins (both successful and failed) to collect data.")
        return
    
    # Handle class imbalance
    if class_counts.get(0, 0) < 3 or class_counts.get(1, 0) < 3:
        print("[train] Very few samples in one or both classes. Using weighted Random Forest.")
        class_weight = 'balanced'
    else:
        # Calculate class weights based on inverse frequency
        n_samples = len(y)
        n_classes = 2
        weight_for_0 = n_samples / (n_classes * class_counts.get(0, 1))
        weight_for_1 = n_samples / (n_classes * class_counts.get(1, 1))
        class_weight = {0: weight_for_0, 1: weight_for_1}
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Random Forest with better parameters
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight=class_weight,
        random_state=42,
        n_jobs=-1
    )
    
    # Handle small datasets with cross-validation
    if len(y) < 20:
        print("[train] Small dataset detected. Using 5-fold cross-validation.")
        cv_scores = cross_val_score(clf, X_scaled, y, cv=min(5, len(y)), scoring='accuracy')
        print(f"[train] Cross-validation accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
        clf.fit(X_scaled, y)
    else:
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\n[train] Training on {len(X_train)} samples, testing on {len(X_test)}")
        
        # Train model
        clf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = clf.predict(X_test)
        y_pred_proba = clf.predict_proba(X_test)[:, 1]
        
        print("\n=== Classification Report ===")
        print(classification_report(y_test, y_pred, target_names=['Fraudulent', 'Legitimate']))
        
        print("\n=== Confusion Matrix ===")
        cm = confusion_matrix(y_test, y_pred)
        print(f"True Negative (TN): {cm[0,0]}")
        print(f"False Positive (FP): {cm[0,1]} (Type I Error - Legit user rejected)")
        print(f"False Negative (FN): {cm[1,0]} (Type II Error - Fraud accepted)")
        print(f"True Positive (TP): {cm[1,1]}")
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nAccuracy: {accuracy:.3f}")
        
        # Feature importance
        feature_names = [
            "dwell_mean", "dwell_std", "dwell_median",
            "flight_mean", "flight_std", "flight_median",
            "total_time", "key_count", "cadence",
            "rhythm_consistency", "pressure_variance",
            "dwell_flight_ratio", "dwell_cv",
            "pattern_entropy", "key_variation", "typing_burstiness"
        ]
        
        importances = clf.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("\n=== Top 10 Most Important Features ===")
        for i in range(min(10, len(feature_names))):
            idx = indices[i]
            feat_name = feature_names[idx] if idx < len(feature_names) else f"Feature_{idx}"
            print(f"{i+1:2}. {feat_name:25} {importances[idx]:.4f}")
    
    # Save model and scaler
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    model_data = {
        'classifier': clf,
        'scaler': scaler,
        'feature_names': feature_names,
        'n_samples': len(y)
    }
    joblib.dump(model_data, MODEL_PATH)
    
    print(f"\n[train] Saved model to {MODEL_PATH}")
    print("[train] This global model is for research/analysis only.")
    print("[train] Authentication uses per-user ensemble models stored in users.json")


if __name__ == "__main__":
    main()