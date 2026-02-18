# ML Training Flow - Keystroke Biometric System

## Overview

The system uses **ensemble machine learning** with adaptive learning to continuously improve user authentication accuracy.

## Key Improvements

### 1. Ensemble Model (Isolation Forest + Local Outlier Factor)
- **Isolation Forest**: Good for high-dimensional anomaly detection
- **Local Outlier Factor**: Good for local density-based anomaly detection
- **Ensemble Decision**: Both must flag as anomaly to reject (reduces false positives)

### 2. Dynamic Thresholds
- Thresholds adapt based on user's typing consistency
- More lenient during initial logins
- Becomes stricter with more data

### 3. Enhanced Feature Set (16 dimensions)
1. dwell_mean
2. dwell_std
3. dwell_median
4. flight_mean
5. flight_std
6. flight_median
7. total_time
8. key_count
9. cadence
10. rhythm_consistency
11. pressure_variance
12. dwell_flight_ratio
13. dwell_cv
14. pattern_entropy
15. key_variation
16. typing_burstiness

## Registration Process (2 Password Entries)

### Step 1: User enters password twice
- Captures keystroke timing patterns from both entries
- Analyzes consistency between the two samples

### Step 2: Initial Model Creation
1. Extracts 16-dimensional feature vectors
2. Trains ensemble model with 2 initial samples
3. Sets dynamic thresholds based on user's natural variation
4. Creates behavioral signature baseline

## Successful Login Training

### Every successful login improves the model:
1. **Captures new keystroke data** → Saved with `label=1`
2. **Loads ALL legitimate samples** for the user
3. **Retrains ensemble model** with expanded dataset
4. **Updates thresholds** based on new data
5. **Adapts template** with learning rate based on confidence

## Temporal Pattern Analysis

### Detects Imitation Attempts:
1. **Tempo Attacks**: Uniform slowdown/speedup detection
2. **Rhythm Similarity**: Compares typing rhythm patterns
3. **Pattern Entropy**: Measures randomness in keystroke sequences
4. **Key Variation**: Analyzes unique key usage patterns

## Benefits

### ✅ Better Fraud Detection
- Ensemble model catches more imposters
- Temporal analysis detects imitation patterns
- Dynamic thresholds adapt to user behavior

### ✅ Improved User Experience
- Less strict for legitimate users
- Adaptive learning accommodates natural variations
- Confidence-based decisions reduce false rejections

### ✅ Continuous Improvement
- Model gets smarter with each login
- Learns from successful authentications
- Maintains security while being user-friendly

## Data Flow
