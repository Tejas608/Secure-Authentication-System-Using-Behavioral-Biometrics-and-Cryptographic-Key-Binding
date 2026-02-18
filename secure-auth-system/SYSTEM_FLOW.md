# Complete System Flow

## 🔐 Registration Flow

```
User Registration
│
├─► Enter Username
├─► Enter Password (Field 1) ────┐
│    └─ Captures: keydown/keyup   │
│       timestamps, key codes      │  Password Samples
│                                  │  Array
├─► Confirm Password (Field 2) ───┤
│    └─ Captures: keydown/keyup   │
│       timestamps, key codes      │
│                                  │
└─► Submit ◄────────────────────────┘
     │
     │ POST /api/register
     │ { username, password, passwordSamples: [sample1, sample2] }
     │
     ▼
Backend Processing
│
├─► Validate password strength
│    └─ 3+ letters, 3+ digits, 1+ special char
│
├─► Extract Features (both samples)
│    ├─ sample1 → feature_vec1 (11 dimensions)
│    └─ sample2 → feature_vec2 (11 dimensions)
│
├─► Create Feature Template
│    └─ avg_vec = mean([feature_vec1, feature_vec2])
│
├─► Train Initial One-Class SVM
│    └─ model.fit([feature_vec1, feature_vec2])
│
├─► Save to CSV (both samples)
│    ├─ username | 1 | session_id_reg_0 | sample1
│    └─ username | 1 | session_id_reg_1 | sample2
│
├─► Generate Crypto Keys
│    ├─ RSA keypair
│    └─ binding_token = bind(public_key, avg_vec)
│
└─► Save to users.json
     ├─ password_hash
     ├─ feature_template
     ├─ user_model (base64)
     ├─ model_samples_count: 2
     └─ crypto binding data
```

## 🔓 Login Flow (with Adaptive Learning)

```
User Login
│
├─► Enter Username
├─► Enter Password
│    └─ Captures: keydown/keyup timestamps
│
└─► Submit
     │
     │ POST /api/login
     │ { username, password, keystrokes: [events] }
     │
     ▼
Backend Authentication Gates
│
├─► Gate 1: Password Verification
│    └─ ❌ Wrong → Save (label=0, tag=fail_pw) → REJECT
│    └─ ✅ Correct → Continue
│
├─► Gate 2: Extract Features
│    └─ feature_vec = extract_features(keystrokes)
│
├─► Gate 3: Tempo Distortion Check
│    └─ Detect uniform slowdown/speedup attacks
│    └─ ❌ Attack → Save (label=0, tag=tempo_attack) → REJECT
│    └─ ✅ Normal → Continue
│
├─► Gate 4: Behavioral Envelope (One-Class SVM)
│    ├─ Load user's model from users.json
│    ├─ decision_score = model.decision_function([feature_vec])
│    └─ ❌ Outside envelope (score < 0) → Continue to final check
│    └─ ✅ Inside envelope (score >= 0) → Continue
│
├─► Gate 5: Rhythm Consistency Check
│    └─ Reject too-smooth typing (likely script/bot)
│    └─ ❌ Too uniform → Save (label=0, tag=entropy_attack) → REJECT
│    └─ ✅ Natural variance → Continue
│
├─► Gate 6: Crypto Binding (policy dependent)
│    └─ verify_binding(public_key, feature_vec, binding_token)
│
└─► Final Decision
     │
     ├─► ❌ REJECT
     │    └─ Save (label=0, tag=fail_behavior)
     │    └─ Return {"ok": false, "message": "Behavioral check failed"}
     │
     └─► ✅ ACCEPT
          │
          ├─► Save to CSV
          │    └─ username | 1 | session_id_success_login | keystrokes
          │
          ├─► Adaptive Learning (Real-time Retraining)
          │    │
          │    ├─ Load ALL legitimate samples from CSV
          │    │   └─ SELECT * WHERE user_id = username AND label = 1
          │    │      ├─ registration samples (2)
          │    │      └─ all past successful logins (N)
          │    │
          │    ├─ Add current login features
          │    │   └─ user_samples.append(feature_vec)
          │    │
          │    ├─ Retrain One-Class SVM
          │    │   └─ new_model = OneClassSVM(nu=0.08)
          │    │       new_model.fit(user_samples)  # Now has 2 + N + 1 samples
          │    │
          │    └─ Update user record
          │         ├─ user_model = base64(new_model)
          │         └─ model_samples_count = len(user_samples)
          │
          ├─► Update Feature Template (adaptive)
          │    └─ template = 0.8 * old_template + 0.2 * new_features
          │
          ├─► Save users.json
          │    └─ Updated model + template
          │
          └─► Return {"ok": true, "message": "Authentication success"}
```

## 📊 Data Flow Over Time

```
Timeline: User's First Week

Day 1 - Registration
├─ Samples: 2
├─ CSV: [reg_0, reg_1]
└─ Model: Baseline (nu=0.15, moderate strictness)

Day 1 - Login #1
├─ Samples: 3 total
├─ CSV: [reg_0, reg_1, success_login]
└─ Model: Retrained with 3 samples

Day 2 - Login #2
├─ Samples: 4 total
├─ CSV: [reg_0, reg_1, success_login, success_login]
└─ Model: Retrained with 4 samples

Day 3 - Login #3 (Failed - wrong typing)
├─ Samples: 4 total (failed not added to training)
├─ CSV: [previous 4 + fail_behavior]
└─ Model: No change (only legitimate samples train)

Day 3 - Login #4
├─ Samples: 5 total
├─ CSV: [previous + success_login]
└─ Model: Retrained with 5 samples (nu=0.08, STRICT mode now)

Day 7 - Login #10
├─ Samples: 12 total
├─ CSV: [2 reg + 10 successful logins]
└─ Model: High accuracy, tight envelope, better security

Imposter Attempt
├─ Password correct but typing different
├─ SVM decision_score = -1.2 (negative = outside envelope)
└─ ❌ REJECTED (saved as label=0, not used for training)
```

## 🎯 Key Points

### 1. **Dual Registration**

- 2 password entries provide initial baseline
- Better than single sample
- Creates initial behavioral signature

### 2. **Continuous Learning**

- Every successful login = +1 training sample
- Model automatically retrains
- No manual intervention needed

### 3. **Data Segregation**

- **label=1**: Registration + successful logins → Used for training
- **label=0**: Failed attempts → Logged for analysis, NOT used for training

### 4. **Security Hardening**

- More logins = tighter envelope
- Model transitions from nu=0.15 (moderate) to nu=0.08 (strict) at 5+ samples
- Better imposter rejection over time

### 5. **Legitimate User Accommodation**

- Learns natural variations (fatigue, mood, keyboard change)
- Adaptive template updates
- Balances security with usability
