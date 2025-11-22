# Testing Guide for Phishing Detection Models

## Overview
This test suite verifies that all 6 ML models are working correctly with the prediction system.

## Test File
`test_all_models.py` - Comprehensive test suite for all models

## How to Run Tests

### 1. Basic Test (Without Dataset)
```bash
cd phish_guard_backend
python test_all_models.py
```

### 2. Test with Dataset
```bash
python test_all_models.py --dataset "path/to/your/dataset.csv"
```

Example:
```bash
python test_all_models.py --dataset "../Document/Explain The Project Step By Step/2-Data Scientist/dataset/1-Phishing website dataset/archive 1/website_phishing.csv"
```

## What Tests Are Performed

### Test 1: Model Loading Status ✅
- Checks if all 6 models are loaded
- Verifies scalers and vectorizer are loaded
- Shows status of each component

### Test 2: Feature Extraction ✅
- Tests numerical feature extraction
- Verifies 9 features are extracted correctly

### Test 3: Whitelist Check ✅
- Tests whitelist functionality
- Verifies trusted domains are recognized

### Test 4: Individual Model Predictions ✅
- Tests each of the 6 models individually:
  - Random Forest (Team 1)
  - LightGBM (Team 1)
  - Logistic Regression (Team 2)
  - SVC (Team 2)
  - XGBoost (Team 3)
  - Neural Network/MLP (Team 3)
- Verifies all 6 models vote correctly

### Test 5: Complete Prediction System ✅
- Tests the full 3-level prediction system:
  1. Whitelist check
  2. AI models voting
  3. HTML analysis (if needed)
- Tests on various URLs (legitimate and phishing)

### Test 6: Dataset Predictions (Optional) 📊
- Tests predictions on your training dataset
- Calculates accuracy on dataset samples
- Compares predictions with actual labels

## Expected Output

```
================================================================================
PHISHING DETECTION MODELS - COMPREHENSIVE TEST SUITE
================================================================================

TEST 1: Model Loading Status
...
✅ All models loaded successfully!

TEST 2: Feature Extraction
...
✅ Feature extraction working correctly!

TEST 3: Whitelist Check
...
✅ All whitelist tests passed!

TEST 4: Individual Model Predictions
...
✅ All 6 models voted successfully!

TEST 5: Complete Prediction System
...
Accuracy: 8/10 (80.0%)

TEST 6: Dataset Predictions (Optional)
...
✅ Dataset Test Accuracy: 8/10 (80.0%)

FINAL TEST SUMMARY
================================================================================
✅ Model Loading
✅ Feature Extraction
✅ Whitelist
✅ Individual Models
✅ Complete System
✅ Dataset

Overall: 6/6 tests passed

🎉 All tests passed successfully!
```

## Troubleshooting

### If models don't load:
- Check that all `.joblib` files exist in `api/ml_model/` directory
- Verify file names match expected names in `predictor.py`

### If feature extraction fails:
- Check that `feature_extractor.py` is working
- Verify numerical features extraction returns 9 values

### If individual models fail:
- Check model file formats (some might be wrapped in dictionaries)
- Verify scalers are extracted correctly from dicts if needed

### If dataset test fails:
- Ensure CSV file exists at specified path
- Check that CSV has URL column (column name containing "url" or "link")
- Verify URLs in dataset start with `http://` or `https://`

## Requirements
- Python 3.7+
- All dependencies installed (pandas, scikit-learn, joblib, etc.)
- All model files present in `api/ml_model/` directory

## Notes
- Test 6 (Dataset) is optional and won't fail if dataset is not provided
- Some tests may show warnings (like feature name warnings) but still pass
- Accuracy may vary depending on test URLs used

