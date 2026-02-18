# Testing Guide - Verify ML Training with Successful Logins

## Quick Test Steps

### 1. Start the Application

```powershell
.\run.ps1
```

### 2. Register a New User

1. Open http://127.0.0.1:5000
2. Click "New user? Register"
3. Enter username: `testuser`
4. Enter password TWICE: `abc123!@#` (meets requirements)
5. Click Register

**What happens:**

- ✅ Both password entries are saved to CSV with `label=1`
- ✅ Initial One-Class SVM model trained with 2 samples
- ✅ Redirected to dashboard

### 3. Check Initial Data

Open `data/keystrokes.csv` - you should see:

```
testuser    1    testuser_<timestamp>_reg_0    [keystroke data]
testuser    1    testuser_<timestamp>_reg_1    [keystroke data]
```

### 4. Log Out and Log In (3-5 times)

1. Go back to http://127.0.0.1:5000
2. Login with same username/password
3. Repeat 3-5 times

**What happens each successful login:**

- ✅ New keystroke data saved with `tag=success_login` and `label=1`
- ✅ Model automatically retrains with ALL label=1 samples
- ✅ Model accuracy improves with each login

### 5. Verify CSV Data

Check `data/keystrokes.csv` again:

```
testuser    1    testuser_<timestamp>_reg_0           [data]
testuser    1    testuser_<timestamp>_reg_1           [data]
testuser    1    testuser_<timestamp>_success_login   [data]
testuser    1    testuser_<timestamp>_success_login   [data]
testuser    1    testuser_<timestamp>_success_login   [data]
```

### 6. Check users.json

```json
{
  "testuser": {
    "user_model": "base64_encoded_svm_model",
    "model_samples_count": 5,  // 2 reg + 3 successful logins
    ...
  }
}
```

## Expected Behavior

### Registration (2 samples)

- ✅ Creates baseline model
- ✅ Both entries saved as legitimate (label=1)

### Each Successful Login

- ✅ Adds to training dataset (label=1)
- ✅ Retrains model with expanded data
- ✅ Improves accuracy over time
- ✅ Updates `model_samples_count`

### Failed Logins

- ✅ Saved with label=0 (not used for training)
- ✅ Tags like `fail_pw`, `fail_behavior`, `tempo_attack`

## Troubleshooting

### No data in CSV after successful login?

- Check [auth.py](backend/auth.py#L404) - should have `_append_dataset_sample(username, 1, events, tag="success_login")`

### Model not updating?

- Check `model_samples_count` in `users.json` - should increase after each login
- Verify `_load_user_samples_for_training` loads label=1 samples only

### Can't login after registration?

- Model might be too strict initially (2 samples)
- Try logging in 2-3 more times to expand behavioral envelope
- Check if `AUTH_POLICY=balanced` (less strict than `strict` mode)

## Monitor Training Progress

### View all legitimate samples for a user:

```powershell
cat data/keystrokes.csv | Select-String "testuser.*\s1\s"
```

### Count samples by label:

```powershell
# Legitimate (label=1)
(cat data/keystrokes.csv | Select-String "testuser.*\s1\s").Count

# Failed (label=0)
(cat data/keystrokes.csv | Select-String "testuser.*\s0\s").Count
```

## Success Metrics

After 5 successful logins, you should have:

- ✅ 7 legitimate samples (2 reg + 5 logins)
- ✅ Model with `nu=0.08` (strict mode)
- ✅ Better rejection of imposters
- ✅ Acceptance of legitimate user variations
