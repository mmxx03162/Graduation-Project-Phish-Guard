"""
Comprehensive Test Suite for Phishing Detection Models
Tests all 6 models individually and the complete prediction system
"""

import sys
import os
import pandas as pd
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import predictor functions
from api.predictor import (
    make_final_prediction,
    get_model_predictions,
    get_models_status,
    check_whitelist
)
from api.feature_extractor import extract_numerical_features

# ═══════════════════════════════════════════════════════════════════════════
# TEST CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Test URLs with expected results
TEST_URLS = [
    # Legitimate URLs (Whitelist)
    ("https://www.google.com", "Legitimate", "Whitelist"),
    ("https://www.youtube.com", "Legitimate", "Whitelist"),
    ("https://www.facebook.com", "Legitimate", "Whitelist"),
    
    # Legitimate URLs (should pass models)
    ("https://www.github.com", "Legitimate", "Models"),
    ("https://www.stackoverflow.com", "Legitimate", "Models"),
    ("https://www.wikipedia.org", "Legitimate", "Models"),
    
    # Phishing URLs
    ("http://paypal-security-update.suspicious-domain.tk/login", "Phishing", "Models"),
    ("https://www.goog1e.com/accounts/signin", "Phishing", "Models"),
    ("http://192.168.1.100/paypal/update.html", "Phishing", "Models"),
    ("https://amazon-account-verification.web.app/confirm", "Phishing", "Models"),
]

# ═══════════════════════════════════════════════════════════════════════════
# TEST FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def test_model_loading():
    """Test if all models are loaded correctly"""
    print("=" * 80)
    print("TEST 1: Model Loading Status")
    print("=" * 80)
    
    status = get_models_status()
    
    loaded_count = sum(1 for s in status.values() if s)
    total_count = len(status)
    
    print(f"\n✓ Loaded: {loaded_count}/{total_count} components")
    
    if loaded_count == total_count:
        print("✅ All models loaded successfully!")
        return True
    else:
        missing = [name for name, loaded in status.items() if not loaded]
        print(f"❌ Missing: {', '.join(missing)}")
        return False

def test_feature_extraction():
    """Test feature extraction for a sample URL"""
    print("\n" + "=" * 80)
    print("TEST 2: Feature Extraction")
    print("=" * 80)
    
    test_url = "https://www.google.com"
    
    try:
        features = extract_numerical_features(test_url)
        print(f"\n✓ URL: {test_url}")
        print(f"✓ Extracted {len(features)} numerical features")
        print(f"✓ Features: {features}")
        
        if len(features) == 9:
            print("✅ Feature extraction working correctly!")
            return True
        else:
            print(f"❌ Expected 9 features, got {len(features)}")
            return False
    except Exception as e:
        print(f"❌ Feature extraction error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_whitelist():
    """Test whitelist functionality"""
    print("\n" + "=" * 80)
    print("TEST 3: Whitelist Check")
    print("=" * 80)
    
    test_cases = [
        ("https://www.google.com", True),
        ("https://www.youtube.com", True),
        ("https://suspicious-domain.com", False),
        ("https://fake-paypal.com", False),
    ]
    
    all_passed = True
    for url, expected in test_cases:
        result = check_whitelist(url)
        status = "✅" if result == expected else "❌"
        print(f"{status} {url}: {result} (expected: {expected})")
        if result != expected:
            all_passed = False
    
    return all_passed

def test_individual_models():
    """Test each model individually"""
    print("\n" + "=" * 80)
    print("TEST 4: Individual Model Predictions")
    print("=" * 80)
    
    test_url = "https://www.github.com"
    print(f"\nTesting URL: {test_url}")
    
    try:
        all_votes, model_details = get_model_predictions(test_url)
        
        print(f"\n✓ Total votes: {len(all_votes)}")
        print(f"✓ Expected: 6 models")
        
        if len(all_votes) == 6:
            print("✅ All 6 models voted successfully!")
            
            print("\nDetailed Results:")
            for detail in model_details:
                icon = "🚨" if detail['vote'] == 1 else "✅"
                print(f"  {icon} {detail['model']}: {detail['label']} ({detail['vote']}) - {detail['type']} - {detail['features']} features")
            
            return True
        else:
            print(f"❌ Expected 6 votes, got {len(all_votes)}")
            print(f"Missing models: {6 - len(all_votes)}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing models: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_complete_prediction_system():
    """Test the complete prediction system"""
    print("\n" + "=" * 80)
    print("TEST 5: Complete Prediction System")
    print("=" * 80)
    
    results = []
    
    for url, expected, test_type in TEST_URLS:
        try:
            prediction_data = make_final_prediction(url)
            verdict = prediction_data.get("verdict")
            reason = prediction_data.get("reason", "")
            
            is_correct = verdict == expected
            icon = "✅" if is_correct else "❌"
            
            results.append({
                'url': url,
                'expected': expected,
                'predicted': verdict,
                'reason': reason,
                'correct': is_correct,
                'test_type': test_type
            })
            
            print(f"\n{icon} {url}")
            print(f"   Expected: {expected}, Got: {verdict}")
            if not is_correct:
                print(f"   Reason: {reason}")
                
        except Exception as e:
            print(f"❌ Error testing {url}: {e}")
            results.append({
                'url': url,
                'expected': expected,
                'predicted': 'Error',
                'reason': str(e),
                'correct': False,
                'test_type': test_type
            })
    
    # Calculate accuracy
    correct = sum(1 for r in results if r['correct'])
    total = len(results)
    accuracy = (correct / total * 100) if total > 0 else 0
    
    print("\n" + "-" * 80)
    print(f"Accuracy: {correct}/{total} ({accuracy:.1f}%)")
    
    # Show incorrect predictions
    incorrect = [r for r in results if not r['correct']]
    if incorrect:
        print(f"\nIncorrect Predictions ({len(incorrect)}):")
        for r in incorrect:
            print(f"  - {r['url']}")
            print(f"    Expected: {r['expected']}, Got: {r['predicted']}")
            print(f"    Reason: {r['reason']}")
    
    return accuracy >= 70  # At least 70% accuracy

def test_dataset_predictions(dataset_path=None):
    """Test predictions on dataset if available"""
    print("\n" + "=" * 80)
    print("TEST 6: Dataset Predictions (Optional)")
    print("=" * 80)
    
    # Try to find dataset files
    possible_paths = [
        "../Document/Explain The Project Step By Step/2-Data Scientist/dataset/1-Phishing website dataset/archive 1/website_phishing.csv",
        "../Document/Explain The Project Step By Step/2-Data Scientist/dataset/2 Phishing Dataset for Machine Learning/archive 2/Phishing_Legitimate_full.csv",
        dataset_path
    ]
    
    dataset_file = None
    for path in possible_paths:
        if path and os.path.exists(path):
            dataset_file = path
            break
    
    if not dataset_file:
        print("⚠️  Dataset file not found. Skipping dataset test.")
        print("   You can provide dataset path as argument to test_dataset_predictions()")
        return None
    
    try:
        print(f"✓ Loading dataset: {dataset_file}")
        df = pd.read_csv(dataset_file)
        
        # Check for URL column
        url_columns = [col for col in df.columns if 'url' in col.lower() or 'link' in col.lower()]
        if not url_columns:
            print("⚠️  No URL column found in dataset. Skipping.")
            return None
        
        url_col = url_columns[0]
        
        # Check for label column
        label_columns = [col for col in df.columns if 'label' in col.lower() or 'result' in col.lower() or 'class' in col.lower()]
        
        # Test on first 10 URLs
        test_size = min(10, len(df))
        print(f"✓ Testing on first {test_size} URLs")
        
        correct = 0
        total = 0
        
        for idx in range(test_size):
            url = str(df.iloc[idx][url_col])
            
            # Skip if URL is invalid
            if pd.isna(url) or not url.startswith(('http://', 'https://')):
                continue
            
            try:
                prediction_data = make_final_prediction(url)
                verdict = prediction_data.get("verdict")
                
                # Check against label if available
                if label_columns:
                    label = df.iloc[idx][label_columns[0]]
                    expected = "Phishing" if label == 1 or label == "Phishing" else "Legitimate"
                    
                    if verdict == expected:
                        correct += 1
                    total += 1
            
            except Exception as e:
                print(f"  ⚠️  Error processing {url}: {e}")
        
        if total > 0:
            accuracy = (correct / total * 100)
            print(f"\n✓ Dataset Test Accuracy: {correct}/{total} ({accuracy:.1f}%)")
            return accuracy >= 70
        else:
            print("⚠️  No valid URLs found in dataset")
            return None
            
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")
        import traceback
        traceback.print_exc()
        return None

# ═══════════════════════════════════════════════════════════════════════════
# MAIN TEST RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_all_tests(dataset_path=None):
    """Run all tests"""
    print("\n" + "=" * 80)
    print("PHISHING DETECTION MODELS - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    
    results = {}
    
    # Test 1: Model Loading
    results['model_loading'] = test_model_loading()
    
    # Test 2: Feature Extraction
    results['feature_extraction'] = test_feature_extraction()
    
    # Test 3: Whitelist
    results['whitelist'] = test_whitelist()
    
    # Test 4: Individual Models
    results['individual_models'] = test_individual_models()
    
    # Test 5: Complete System
    results['complete_system'] = test_complete_prediction_system()
    
    # Test 6: Dataset (Optional)
    dataset_result = test_dataset_predictions(dataset_path)
    if dataset_result is not None:
        results['dataset'] = dataset_result
    
    # Final Summary
    print("\n" + "=" * 80)
    print("FINAL TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for test_name, result in results.items():
        icon = "✅" if result else "❌"
        print(f"{icon} {test_name.replace('_', ' ').title()}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed successfully!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
    
    return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Test Phishing Detection Models')
    parser.add_argument('--dataset', type=str, help='Path to dataset CSV file')
    args = parser.parse_args()
    
    run_all_tests(dataset_path=args.dataset)

