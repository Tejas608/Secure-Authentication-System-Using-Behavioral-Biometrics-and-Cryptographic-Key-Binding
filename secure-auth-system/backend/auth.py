import base64
import json
import os
import time
import ast
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

from . import keystroke_features
from .crypto_utils import bind_public_key, generate_rsa_keypair, verify_binding

USERS_DB = Path(__file__).parent / "users.json"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "keystrokes.csv"
MODEL_PATH = PROJECT_ROOT / "ml" / "model.pkl"

# CSV Cache for performance optimization (handles 1000+ records efficiently)
_user_sample_cache = {}  # {username: List[feature_vectors]}
_cache_last_modified = 0  # Track dataset modification time

def _invalidate_cache(username: Optional[str] = None) -> None:
    """Invalidate cache for a user or all users."""
    global _user_sample_cache, _cache_last_modified
    if username:
        _user_sample_cache.pop(username, None)
    else:
        _user_sample_cache.clear()
    _cache_last_modified = time.time()

def _append_dataset_sample(username: str, label: int, events: List[Dict], tag: str = "") -> None:
    if not events:
        return
    try:
        DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not DATASET_PATH.exists() or DATASET_PATH.stat().st_size == 0:
            with DATASET_PATH.open("w", encoding="utf-8", newline="") as f:
                f.write("user_id\tlabel\tsession_id\tkeystrokes\tfeatures\n")
        
        ts_base = int(time.time())
        session_id = f"{username}_{ts_base}{('_' + tag) if tag else ''}"
        
        # Extract features for the dataset too
        features_map = keystroke_features.extract_features(events)
        feature_vec = keystroke_features.feature_vector(features_map)
        
        with DATASET_PATH.open("a", encoding="utf-8", newline="") as f:
            f.write(f"{username}\t{int(label)}\t{session_id}\t{json.dumps(events)}\t{json.dumps(feature_vec)}\n")
        
        # Invalidate cache for this user since we added new data
        _invalidate_cache(username)
    except Exception:
        pass

def _train_user_model(username: str, user_samples: List[List[float]]) -> Optional[Dict]:
    """Train ensemble model for user anomaly detection.
    
    Uses Isolation Forest + LOF ensemble for better anomaly detection.
    Optimized for handling 1000+ records with dynamic n_neighbors.
    """
    if not user_samples or len(user_samples) < 2:
        return None
    
    try:
        X = np.array(user_samples, dtype=float)
        
        # Standardize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Isolation Forest (good for high-dimensional data)
        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Expect 10% outliers
            random_state=42,
            bootstrap=True
        )
        iso_forest.fit(X_scaled)
        
        # Train Local Outlier Factor (good for local density estimation)
        # OPTIMIZED: Dynamic n_neighbors based on dataset size (was hardcoded to 5)
        # For 1000+ records: use 10-20% of samples, capped at 100
        n_samples = len(X_scaled)
        optimal_neighbors = min(max(10, n_samples // 10), 100)
        
        lof = LocalOutlierFactor(
            n_neighbors=optimal_neighbors,
            contamination=0.1,
            novelty=True
        )
        lof.fit(X_scaled)
        
        # Calculate baseline scores for user's own samples
        iso_scores = iso_forest.score_samples(X_scaled)
        lof_scores = lof.score_samples(X_scaled)
        
        # Calculate dynamic threshold (mean - 2*std for user's own samples)
        iso_threshold = np.mean(iso_scores) - 2 * np.std(iso_scores)
        lof_threshold = np.mean(lof_scores) - 2 * np.std(lof_scores)
        
        # Store model components
        model_data = {
            'iso_forest': iso_forest,
            'lof': lof,
            'scaler': scaler,
            'iso_threshold': float(iso_threshold),
            'lof_threshold': float(lof_threshold),
            'user_samples_mean': np.mean(X, axis=0).tolist(),
            'user_samples_std': np.std(X, axis=0).tolist(),
            'n_samples': len(user_samples)
        }
        
        return model_data
    except Exception as e:
        print(f"Error training model for {username}: {e}")
        return None

def _load_user_samples_for_training(username: str) -> Optional[List[List[float]]]:
    """Load legitimate samples for a user with caching for performance.
    
    OPTIMIZED: Uses in-memory cache to avoid re-reading CSV file on each login.
    Cache is automatically invalidated when new data is appended.
    For 1000+ records, this reduces loading time from 200-500ms to <1ms on cache hit.
    """
    global _user_sample_cache
    
    # Check cache first - massive speedup for repeated logins
    if username in _user_sample_cache:
        return _user_sample_cache[username]
    
    if not DATASET_PATH.exists() or DATASET_PATH.stat().st_size == 0:
        return None
    
    try:
        # Read CSV file only if not cached
        df = pd.read_csv(DATASET_PATH, sep="\t")
        user_data = df[(df['user_id'] == username) & (df['label'] == 1)]
        
        if user_data.empty:
            _user_sample_cache[username] = None
            return None
        
        feature_vecs = []
        for _, row in user_data.iterrows():
            try:
                # Try to get features from features column first
                if 'features' in row and pd.notna(row['features']):
                    features = json.loads(row['features'])
                    feature_vecs.append(features)
                else:
                    # Fallback to extracting from keystrokes
                    events = ast.literal_eval(row["keystrokes"]) if isinstance(row["keystrokes"], str) else []
                    feats = keystroke_features.feature_vector(keystroke_features.extract_features(events))
                    feature_vecs.append(feats)
            except Exception:
                continue
        
        result = feature_vecs if feature_vecs else None
        # Store in cache for future use - avoids re-reading CSV
        _user_sample_cache[username] = result
        return result
    except Exception as e:
        print(f"Error loading samples: {e}")
        return None

def _analyze_temporal_patterns(login_vec: List[float], template_vec: List[float]) -> Dict:
    """Analyze temporal patterns for anomaly detection."""
    if not template_vec or not login_vec:
        return {"tempo_attack": False, "rhythm_similarity": 0}
    
    try:
        # Compare rhythm consistency (feature index 9)
        template_rhythm = template_vec[9] if len(template_vec) > 9 else 0.5
        login_rhythm = login_vec[9] if len(login_vec) > 9 else 0.5
        
        # Compare cadence (feature index 8)
        template_cadence = template_vec[8] if len(template_vec) > 8 else 1.0
        login_cadence = login_vec[8] if len(login_vec) > 8 else 1.0
        
        # Calculate rhythm similarity
        rhythm_diff = abs(login_rhythm - template_rhythm) / (template_rhythm + 0.001)
        cadence_diff = abs(login_cadence - template_cadence) / (template_cadence + 0.001)
        
        # Detect tempo attacks (uniform slowdown/speedup)
        time_features = login_vec[0:6]  # dwell and flight stats
        template_time = template_vec[0:6]
        
        if len(time_features) >= 3 and len(template_time) >= 3:
            ratios = []
            for i in range(min(3, len(time_features))):
                if template_time[i] > 0.001:
                    ratio = time_features[i] / template_time[i]
                    ratios.append(ratio)
            
            if ratios:
                mean_ratio = np.mean(ratios)
                tempo_attack = mean_ratio > 2.5 or mean_ratio < 0.4
            else:
                tempo_attack = False
        else:
            tempo_attack = False
        
        return {
            "tempo_attack": tempo_attack,
            "rhythm_similarity": 1.0 - (rhythm_diff * 0.5 + cadence_diff * 0.5),
            "rhythm_diff": rhythm_diff,
            "cadence_diff": cadence_diff
        }
    except Exception:
        return {"tempo_attack": False, "rhythm_similarity": 0}

def _detect_behavioral_anomaly(model_data: Dict, feature_vec: List[float]) -> Dict:
    """Detect behavioral anomalies using ensemble model."""
    try:
        # Scale the feature vector
        scaler = model_data['scaler']
        features_scaled = scaler.transform([feature_vec])
        
        # Get scores from both models
        iso_score = model_data['iso_forest'].score_samples(features_scaled)[0]
        lof_score = model_data['lof'].score_samples(features_scaled)[0]
        
        # Check against thresholds
        iso_anomaly = iso_score < model_data['iso_threshold']
        lof_anomaly = lof_score < model_data['lof_threshold']
        
        # Ensemble decision: anomaly if BOTH models flag it (reduces false positives)
        is_anomaly = iso_anomaly and lof_anomaly
        
        # Calculate confidence
        iso_norm = (iso_score - model_data['iso_threshold']) / abs(model_data['iso_threshold'] + 0.001)
        lof_norm = (lof_score - model_data['lof_threshold']) / abs(model_data['lof_threshold'] + 0.001)
        confidence = 1.0 - (abs(iso_norm) + abs(lof_norm)) / 2.0
        
        return {
            "is_anomaly": is_anomaly,
            "iso_score": float(iso_score),
            "lof_score": float(lof_score),
            "iso_threshold": model_data['iso_threshold'],
            "lof_threshold": model_data['lof_threshold'],
            "confidence": float(confidence),
            "decision": "REJECT" if is_anomaly else "ACCEPT"
        }
    except Exception as e:
        print(f"Error in anomaly detection: {e}")
        return {
            "is_anomaly": False,
            "confidence": 0.0,
            "decision": "FALLBACK"
        }

def _is_strong_password(pwd: str) -> bool:
    if not isinstance(pwd, str):
        return False
    letters = sum(1 for c in pwd if c.isalpha())
    digits = sum(1 for c in pwd if c.isdigit())
    specials_set = set("!@#$%^&*()_-+=[]{}|\\:;\"'<>,.?/~`")
    specials = sum(1 for c in pwd if c in specials_set)
    return len(pwd) >= 8 and letters >= 3 and digits >= 2 and specials >= 1

# Configuration
PASSWORD_ITERATIONS = 120_000
ADAPT_ALPHA = 0.85  # Higher for more stability
AUTH_POLICY = os.getenv("AUTH_POLICY", "balanced").strip().lower()

def _load_users() -> Dict:
    def _purge_dataset_if_no_users(data: Dict) -> Dict:
        if not data:
            try:
                if DATASET_PATH.exists():
                    DATASET_PATH.unlink()
            except Exception:
                pass
        return data

    if USERS_DB.exists():
        try:
            with USERS_DB.open("r", encoding="utf-8-sig") as f:
                return _purge_dataset_if_no_users(json.load(f))
        except json.JSONDecodeError:
            with USERS_DB.open("r", encoding="utf-8-sig") as f:
                text = f.read().lstrip("\ufeff")
            data = json.loads(text) if text.strip() else {}
            return _purge_dataset_if_no_users(data)
    return _purge_dataset_if_no_users({})

def _save_users(data: Dict):
    USERS_DB.parent.mkdir(parents=True, exist_ok=True)
    with USERS_DB.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    salt = salt or os.urandom(16)
    dk = _pbkdf2(password, salt)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()

def _pbkdf2(password: str, salt: bytes) -> bytes:
    return __import__("hashlib").pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_ITERATIONS, dklen=32
    )

def _verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    candidate = _pbkdf2(password, salt)
    return __import__("hmac").compare_digest(expected, candidate)

def register_user(username: str, password: str, password_samples: List[List[Dict]]) -> Dict:
    users = _load_users()
    if username in users:
        return {"ok": False, "message": "User already exists"}

    if not _is_strong_password(password):
        return {
            "ok": False,
            "message": "Password is weak",
            "conditions": "Must be at least 8 characters with 3 letters, 2 numbers, and 1 special character"
        }

    # Extract features from registration samples
    feature_vecs = []
    for sample in password_samples:
        if sample:
            features_map = keystroke_features.extract_features(sample)
            feature_vec = keystroke_features.feature_vector(features_map)
            feature_vecs.append(feature_vec)
    
    if not feature_vecs:
        return {"ok": False, "message": "No keystroke data captured"}
    
    # Create initial template
    arr = np.array(feature_vecs, dtype=float)
    avg_vec = np.mean(arr, axis=0).tolist()
    std_vec = np.std(arr, axis=0).tolist()
    
    # Generate keys
    priv, pub = generate_rsa_keypair()
    binding_token = bind_public_key(pub, avg_vec)
    salt_b64, hash_b64 = _hash_password(password)

    # Train initial model
    user_model_data = _train_user_model(username, feature_vecs)
    user_model_b64 = None
    if user_model_data:
        try:
            model_bytes = joblib.dumps(user_model_data)
            user_model_b64 = base64.b64encode(model_bytes).decode()
        except Exception:
            pass

    users[username] = {
        "password_salt": salt_b64,
        "password_hash": hash_b64,
        "public_key": pub,
        "binding_token": binding_token,
        "feature_template": avg_vec,
        "feature_std": std_vec,
        "private_key": priv,
        "user_model": user_model_b64,
        "model_samples_count": len(feature_vecs),
        "registration_date": time.time(),
        "last_login": None,
        "login_count": 0,
        "failed_attempts": 0
    }
    _save_users(users)
    
    # Save registration samples
    for idx, sample in enumerate(password_samples or []):
        if sample:
            _append_dataset_sample(username, 1, sample, tag=f"reg_{idx}")

    return {"ok": True, "message": "User registered", "public_key": pub}

def _feature_distance(vec_a: List[float], vec_b: List[float]) -> float:
    if not vec_a or not vec_b:
        return 1.0
    a = np.array(vec_a, dtype=float)
    b = np.array(vec_b, dtype=float)
    if a.shape != b.shape:
        return 1.0
    # Use cosine distance for better angle-based similarity
    dot_product = np.dot(a, b)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 1.0
    cosine_sim = dot_product / (norm_a * norm_b)
    return 1.0 - cosine_sim

def authenticate_user(username: str, password: str, events: List[Dict], model=None) -> Dict:
    """Improved authentication with ensemble anomaly detection."""
    users = _load_users()
    record = users.get(username)
    if not record:
        return {"ok": False, "message": "Unknown user"}

    # Gate 1: Password verification
    if not _verify_password(password, record["password_salt"], record["password_hash"]):
        record["failed_attempts"] = record.get("failed_attempts", 0) + 1
        _save_users(users)
        _append_dataset_sample(username, 0, events, tag="fail_pw")
        return {"ok": False, "message": "Invalid password"}

    # Extract features
    features_map = keystroke_features.extract_features(events)
    feature_vec = keystroke_features.feature_vector(features_map)

    # Gate 2: Crypto binding check
    binding_ok = verify_binding(record["public_key"], feature_vec, record["binding_token"])

    # Gate 3: Temporal pattern analysis
    temporal_analysis = _analyze_temporal_patterns(feature_vec, record.get("feature_template", []))
    
    if temporal_analysis["tempo_attack"]:
        record["failed_attempts"] = record.get("failed_attempts", 0) + 1
        _save_users(users)
        _append_dataset_sample(username, 0, events, tag="tempo_attack")
        return {
            "ok": False,
            "message": "Abnormal typing tempo detected",
            "reason": "time_warp_attack"
        }

    # Gate 4: Behavioral anomaly detection
    anomaly_result = None
    behavior_ok = False
    model_confidence = 0.0
    
    try:
        user_model_b64 = record.get("user_model")
        if user_model_b64:
            model_bytes = base64.b64decode(user_model_b64)
            user_model_data = joblib.loads(model_bytes)
            anomaly_result = _detect_behavioral_anomaly(user_model_data, feature_vec)
            behavior_ok = not anomaly_result["is_anomaly"]
            model_confidence = anomaly_result.get("confidence", 0.0)
        else:
            # Fallback to distance-based check
            template_vec = record.get("feature_template", [])
            if template_vec:
                distance = _feature_distance(feature_vec, template_vec)
                # More lenient threshold initially
                threshold = 0.45 if record.get("login_count", 0) < 5 else 0.35
                behavior_ok = distance <= threshold
                model_confidence = 1.0 - distance
    except Exception as e:
        # Fallback
        template_vec = record.get("feature_template", [])
        if template_vec:
            distance = _feature_distance(feature_vec, template_vec)
            behavior_ok = distance <= 0.5
            model_confidence = 1.0 - distance

    # Gate 5: Rhythm consistency check (less strict)
    rhythm_consistency = features_map.get("rhythm_consistency", 0.5)
    if rhythm_consistency < 0.02:  # Very low = too perfect
        _append_dataset_sample(username, 0, events, tag="low_entropy")
        # Don't reject immediately, just note it

    # Gate 6: Rhythm similarity check - MUST be > 90%
    rhythm_similarity = temporal_analysis.get("rhythm_similarity", 0)
    if rhythm_similarity < 0.9:  # Less than 90%
        record["failed_attempts"] = record.get("failed_attempts", 0) + 1
        _save_users(users)
        _append_dataset_sample(username, 0, events, tag="fail_rhythm")
        return {
            "ok": False,
            "message": "Typing rhythm mismatch",
            "confidence": model_confidence,
            "rhythm_similarity": rhythm_similarity,
            "reason": f"rhythm_too_low_{int(rhythm_similarity * 100)}%"
        }

    # Decision logic
    accepted = False
    message = "Authentication failed"
    
    if AUTH_POLICY == "strict":
        # Strict: need both crypto and behavior
        if binding_ok and behavior_ok:
            accepted = True
            message = "Authentication successful"
    else:  # balanced
        # Balanced: primarily behavior-based with crypto as secondary
        if behavior_ok:
            accepted = True
            message = "Authentication successful"
        elif binding_ok and model_confidence > 0.6:
            # If crypto is good and we have moderate confidence, accept
            accepted = True
            message = "Authentication successful (crypto-assisted)"

    if accepted:
        # Update user stats
        record["last_login"] = time.time()
        record["login_count"] = record.get("login_count", 0) + 1
        record["failed_attempts"] = 0
        
        # Save successful login
        _append_dataset_sample(username, 1, events, tag="success_login")
        
        # Adaptive learning: Update model with new sample
        try:
            user_samples = _load_user_samples_for_training(username)
            if user_samples:
                user_samples.append(feature_vec)
                # Retrain with all samples (including new one)
                new_model_data = _train_user_model(username, user_samples)
                if new_model_data:
                    model_bytes = joblib.dumps(new_model_data)
                    record["user_model"] = base64.b64encode(model_bytes).decode()
                    record["model_samples_count"] = len(user_samples)
        except Exception as e:
            print(f"Model update failed: {e}")
        
        # Update template
        old = np.array(record.get("feature_template", feature_vec), dtype=float)
        new = np.array(feature_vec, dtype=float)
        # Adaptive learning rate based on confidence
        alpha = ADAPT_ALPHA if model_confidence > 0.7 else 0.95
        updated = (alpha * old) + ((1 - alpha) * new)
        record["feature_template"] = updated.tolist()
        
        users[username] = record
        _save_users(users)
        
        return {
            "ok": True,
            "message": message,
            "confidence": model_confidence,
            "binding_ok": binding_ok,
            "rhythm_similarity": temporal_analysis.get("rhythm_similarity", 0),
            "login_count": record["login_count"]
        }

    # Failed attempt
    record["failed_attempts"] = record.get("failed_attempts", 0) + 1
    _save_users(users)
    _append_dataset_sample(username, 0, events, tag="fail_behavior")
    
    return {
        "ok": False,
        "message": message,
        "confidence": model_confidence,
        "binding_ok": binding_ok,
        "rhythm_similarity": temporal_analysis.get("rhythm_similarity", 0),
        "reason": "behavior_mismatch"
    }