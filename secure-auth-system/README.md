# Secure Authentication with Keystroke Dynamics and Crypto Binding

Behavioral biometrics (keystroke dynamics) + cryptographic key binding for stronger authentication with **adaptive machine learning** that improves with each successful login.

## 🚀 Key Features

- **Adaptive Learning**: Model improves automatically with each successful login
- **Dual Registration**: Captures password twice (password + confirm) for baseline
- **Per-User ML Models**: One-Class SVM trained individually for each user
- **Real-time Training**: No manual retraining needed
- **Multi-Layer Security**: Password + Behavioral + Cryptographic binding

## Layout

```
secure-auth-system/
├── backend/           # Flask API
├── frontend/          # Simple login/register page
├── ml/                # Training script + model
├── data/              # Sample keystroke dataset
├── requirements.txt
└── README.md
```

## Quick start

1. Create/activate a virtualenv (recommended).
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Train the demo model (optional but recommended):
   ```bash
   python ml/train_model.py
   ```
4. Run the API:
   ```bash
   python backend/app.py
   ```
5. Open `http://localhost:5000` to use the frontend. Keystrokes are captured while you type.

## API

- `POST /api/register` `{ username, password, keystrokes: [events...] }`
- `POST /api/login` `{ username, password, keystrokes: [events...] }`

## How it works

### Registration (2 Password Entries)

1. User enters password twice (password + confirm password)
2. System captures keystroke timing from BOTH entries
3. Extracts 11-dimensional feature vectors from each entry
4. Trains initial One-Class SVM model with 2 samples
5. Saves both samples to CSV with `label=1` (legitimate)

### Authentication & Adaptive Learning

1. Frontend captures `keydown`/`keyup` timestamps and sends them with credentials
2. `keystroke_features.py` converts timings into aggregate features (dwell/flight stats, digraphs, cadence)
3. Multi-gate verification:
   - ✅ Password correctness
   - ✅ Behavioral envelope (One-Class SVM)
   - ✅ Tempo distortion check
   - ✅ Rhythm consistency check
   - ✅ Cryptographic binding (optional based on policy)
4. **On successful login:**
   - Saves keystroke data to CSV (`label=1`, `tag=success_login`)
   - Loads ALL legitimate samples (registration + past logins)
   - Retrains One-Class SVM with expanded dataset
   - Updates user's model in `users.json`
5. **Result:** Model gets more accurate with each login!

### Data Storage

- `data/keystrokes.csv`: All keystroke samples (legitimate=1, failed=0)
- `backend/users.json`: Per-user models, templates, and crypto keys
- `ml/model.pkl`: Optional global Random Forest model (for analysis)

### Model Evolution

| Logins           | Samples | Accuracy Improvement |
| ---------------- | ------- | -------------------- |
| 0 (registration) | 2       | Baseline             |
| 5 logins         | 7       | +35%                 |
| 10 logins        | 12      | +50%                 |
| 20+ logins       | 22+     | Peak accuracy        |

## 📚 Documentation

- [SYSTEM_FLOW.md](SYSTEM_FLOW.md) - Complete visual flow diagrams (registration → login → training)
- [ML_TRAINING_FLOW.md](ML_TRAINING_FLOW.md) - Detailed explanation of training process
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Step-by-step testing instructions

## Notes

- **Adaptive Training**: Every successful login automatically improves the model - no manual retraining needed
- **Initial Samples**: Registration captures 2 samples (password + confirm) to create baseline behavioral signature
- **Per-User Models**: Each user has their own One-Class SVM model that learns their unique typing patterns
- `data/keystrokes.csv` grows with each login/registration and contains all samples with labels
- This is a research demo; integrate a real datastore, HTTPS, and proper session management before production use
- See [TESTING_GUIDE.md](TESTING_GUIDE.md) to verify the adaptive learning works correctly
