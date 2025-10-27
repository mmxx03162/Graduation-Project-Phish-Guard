# api/predictor.py
# Machine Learning Prediction Engine for Phish-Guard
# This module handles loading machine learning models and making predictions on URLs

import os
from collections import Counter
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Import joblib with fallback for graceful degradation
try:
    import joblib
    import sklearn
    JOBLIB_AVAILABLE = True
    SKLEARN_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Required ML libraries not installed ({e}). Using fallback prediction.")
    JOBLIB_AVAILABLE = False
    SKLEARN_AVAILABLE = False

# Import feature extraction module
from .feature_extractor import (
    validate_url,
)

# Define base directory and model directory paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'ml_model')

# List of numerical feature names for Team 1
NUMERICAL_FEATURE_NAMES = [
    'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
    'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
]

# Label mapping for consistent prediction results
LABEL_TO_INT = {
    # phishing-like labels
    'phishing': 1,
    'malicious': 1,
    'spam': 1,
    'unsafe': 1,
    # legitimate-like labels
    'legitimate': 0,
    'benign': 0,
    'safe': 0,
    'clean': 0,
}

def extract_team2_features(url):
    """
    Extract numerical features for Team 2 in the correct order.
    
    This function extracts features according to the training code:
    ['UrlLength', 'HostnameLength', 'NumDots', 'NumDash', 
     'AtSymbol', 'NumQueryComponents', 'PathLength', 'NumNumericChars', 'NoHttps']
    
    Args:
        url (str): The URL to extract features from
        
    Returns:
        list: List of numerical features in the expected order
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    path = parsed.path
    
    features = [
        len(url),  # UrlLength
        len(hostname),  # HostnameLength
        hostname.count('.'),  # NumDots
        hostname.count('-'),  # NumDash
        1 if '@' in url else 0,  # AtSymbol
        sum(1 for part in parsed.query.split('&') if part) if parsed.query else 0,  # NumQueryComponents
        len(path) if path else 0,  # PathLength
        sum(c.isdigit() for c in url),  # NumNumericChars
        0 if url.startswith('https://') else 1,  # NoHttps
    ]
    
    return features


def normalize_prediction(raw_value, proba_threshold: float = 0.5) -> int:
    """
    Normalize model outputs to 0 (Legitimate) or 1 (Phishing).

    This function handles various output formats from different models:
    - Integer/boolean labels {0,1} or {-1,1}
    - Floats as probabilities in [0,1]
    - Strings like "phishing"/"legitimate"
    
    Args:
        raw_value: The raw prediction value from the model
        proba_threshold (float): Threshold for probability-based predictions
        
    Returns:
        int: Normalized prediction (0 for legitimate, 1 for phishing)
    """
    # Unwrap arrays/lists
    if isinstance(raw_value, (list, tuple, np.ndarray)) and len(raw_value) > 0:
        raw_value = raw_value[0]

    # Handle string labels mapping
    if isinstance(raw_value, str):
        label = raw_value.strip().lower()
        if label in LABEL_TO_INT:
            return LABEL_TO_INT[label]
        # Unknown strings default to legitimate to avoid unsafe bias
        return 0

    # Handle boolean values
    if isinstance(raw_value, bool):
        return 1 if raw_value else 0

    # Handle numeric types
    try:
        value = float(raw_value)
    except Exception:
        # Unknown type -> conservative default: Legitimate (0)
        return 0

    # Handle probabilities in [0,1]
    if 0.0 <= value <= 1.0:
        return 1 if value >= proba_threshold else 0

    # Handle classification labels where <=0 is legitimate, >0 phishing
    return 1 if value > 0 else 0

def load_model(filename):
    """
    Helper function to load models and avoid code duplication.
    
    This function handles loading machine learning models from joblib files,
    supporting both direct model files and dictionary-wrapped models with metadata.
    
    Args:
        filename (str): Name of the model file to load
        
    Returns:
        tuple: (model, threshold) or (None, None) if loading fails
    """
    if not JOBLIB_AVAILABLE or not SKLEARN_AVAILABLE:
        print(f"Cannot load {filename}: Required ML libraries not available")
        return None, None
       
    try:
        path = os.path.join(MODEL_DIR, filename)
        if os.path.exists(path):
            loaded_data = joblib.load(path)
            
            # Check if the model is saved in a dictionary format
            if isinstance(loaded_data, dict) and 'model' in loaded_data:
                # Extract model and threshold from the dictionary
                model = loaded_data['model']
                threshold = loaded_data.get('threshold', 0.5)
                feature_names = loaded_data.get('feature_names', None)

                # Print additional information (safe with numpy arrays)
                if feature_names is not None:
                    try:
                        n_features = len(feature_names)
                    except Exception:
                        n_features = 'unknown'
                    print(f"Successfully loaded: {filename} (with {n_features} features, threshold={threshold:.3f})")
                else:
                    print(f"Successfully loaded: {filename} (threshold={threshold:.3f})")

                return model, threshold
            else:
                # Model is saved directly without dictionary wrapper
                print(f"Successfully loaded: {filename} (using default threshold=0.5)")
                return loaded_data, 0.5
        else:
            print(f"File not found: {path}")
            return None, None
    except Exception as e:
        print(f"Error loading {filename}: {e}")
        return None, None

# --- Load all models ---
print("Loading all models...")

# Load Team 1 models (Numerical Features)
model_1_1_rf, threshold_1_1 = load_model('new_model_1_1_rf.joblib')
model_1_2_lgbm, threshold_1_2 = load_model('new_model_1_2_lgbm.joblib')

# Load Team 2 models and tools (Numerical Features)
model_2_1_lr, threshold_2_1 = load_model('new_model_2_1_lr.joblib')
model_2_2_svc, threshold_2_2 = load_model('new_model_2_2_svc.joblib')
scaler_team2, _ = load_model('new_scaler_team2.joblib')  # StandardScaler for Team 2

# Load Team 3 models and tools (Combined Features)
model_3_1_xgb, threshold_3_1 = load_model('new_model_3_1_xgb.joblib')
model_3_2_mlp, threshold_3_2 = load_model('new_model_3_2_mlp.joblib')
vectorizer_team3, _ = load_model('new_tfidf_vectorizer_team3.joblib')
scaler_team3, _ = load_model('new_scaler_team3.joblib')

# Group models by type for organization
numerical_models = {
    'Random Forest': model_1_1_rf,
    'LightGBM': model_1_2_lgbm,
    'XGBoost': model_3_1_xgb,
    'Neural Network': model_3_2_mlp
}

def predict_with_threshold(model, features, threshold, model_name):
    """
    Enhanced prediction function with custom threshold support.
    
    This function supports both predict and predict_proba methods,
    using the custom threshold for probability-based predictions.
    
    Args:
        model: The machine learning model to use for prediction
        features: The feature matrix to predict on
        threshold (float): The threshold for probability-based predictions
        model_name (str): Name of the model for error reporting
        
    Returns:
        int: Prediction result (0 for legitimate, 1 for phishing) or None if error
    """
    try:
        # Try to use predict_proba to get probabilities
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(features)
            if proba.shape[1] == 2:  # Binary classification
                # Use the custom threshold
                prediction = int(proba[0, 1] >= threshold)
                return prediction
        
        # Fallback: use regular predict with normalize_prediction
        raw_pred = model.predict(features)[0]
        prediction = normalize_prediction(raw_pred, threshold)
        return prediction
        
    except Exception as e:
        print(f"  ✗ {model_name} error: {e}")
        return None


def make_prediction(url: str, metadata: dict = None) -> str:
    """
    Main function that manages the voting process between all six expert models.
    
    This function coordinates the prediction process by:
    1. Extracting features from the URL
    2. Running predictions through multiple models
    3. Collecting votes from all models
    4. Making a final decision based on majority voting
    
    Args:
        url (str): The URL to analyze
        metadata (dict, optional): Additional metadata for the analysis
    
    Returns:
        str: "Phishing" or "Legitimate" based on the final decision
    """
    # Fallback prediction if required libraries not available
    if not JOBLIB_AVAILABLE or not SKLEARN_AVAILABLE:
        return "Phishing"  # Default to safe option
    
    # Validate the URL format
    if not validate_url(url):
        print(f"Invalid URL format: {url}")
        return "Error: Invalid URL format"
    
    if metadata is None:
        metadata = {}
    
    all_votes = []
    
    print(f"\n{'='*60}")
    print(f"🔍 Analyzing URL: {url}")
    print(f"{'='*60}")
    
    # --- Extract numerical features ---
    print("\n📊 Extracting numerical features...")
    
    # Team 1 features
    from .feature_extractor import PhishingFeatureExtractor
    extractor_t1 = PhishingFeatureExtractor()
    team1_df = extractor_t1.get_feature_dataframe(url)

    # Team 3 features - simplified numerical features
    from .feature_extractor import extract_numerical_features
    numerical_features_list = extract_numerical_features(url)
    numerical_features_df = pd.DataFrame([numerical_features_list], columns=NUMERICAL_FEATURE_NAMES)
    print(f"✓ Extracted {len(numerical_features_list)} numerical features")
    
    # --- 1. Numerical experts voting (Team 1 + part of Team 3) ---
    print(f"\n{'─'*60}")
    print("🤖 Team 1: Numerical Models Predictions")
    print(f"{'─'*60}")
    
    # Random Forest
    if model_1_1_rf:
        try:
            # Use DataFrame matching the training column names for this model
            prediction = predict_with_threshold(
                model_1_1_rf, 
                team1_df, 
                threshold_1_1 if threshold_1_1 else 0.5,
                "Random Forest"
            )
            if prediction is not None:
                all_votes.append(prediction)
                status = "🚨 Phishing" if prediction == 1 else "✅ Legitimate"
                print(f"  ✓ Random Forest: {status}")
        except Exception as e:
            print(f"  ✗ Random Forest error: {e}")
    else:
        print(f"  ✗ Random Forest: Not loaded")
    
    # LightGBM
    if model_1_2_lgbm:
        try:
            # Some LightGBM versions don't check column names, but we pass the same team1_df for consistency
            prediction = predict_with_threshold(
                model_1_2_lgbm, 
                team1_df,
                threshold_1_2 if threshold_1_2 else 0.5,
                "LightGBM"
            )
            if prediction is not None:
                all_votes.append(prediction)
                status = "🚨 Phishing" if prediction == 1 else "✅ Legitimate"
                print(f"  ✓ LightGBM: {status}")
        except Exception as e:
            print(f"  ✗ LightGBM error: {e}")
    else:
        print(f"  ✗ LightGBM: Not loaded")

    # --- 2. Numerical features experts voting (Team 2) ---
    print(f"\n{'─'*60}")
    print("📊 Team 2: Numerical Features Models Predictions")
    print(f"{'─'*60}")
    
    if scaler_team2:
        try:
            # Extract numerical features for Team 2
            team2_features = extract_team2_features(url)
            team2_features_df = pd.DataFrame([team2_features], columns=[
                'UrlLength', 'HostnameLength', 'NumDots', 'NumDash', 'AtSymbol',
                'NumQueryComponents', 'PathLength', 'NumNumericChars', 'NoHttps'
            ])
            
            # Apply StandardScaler
            scaled_features = scaler_team2.transform(team2_features_df)
            
            # Logistic Regression with custom threshold
            if model_2_1_lr:
                try:
                    prediction = predict_with_threshold(
                        model_2_1_lr,
                        scaled_features,
                        threshold_2_1 if threshold_2_1 else 0.5,
                        "Logistic Regression"
                    )
                    if prediction is not None:
                        all_votes.append(prediction)
                        status = "🚨 Phishing" if prediction == 1 else "✅ Legitimate"
                        print(f"  ✓ Logistic Regression: {status}")
                except Exception as e:
                    print(f"  ✗ Logistic Regression error: {e}")
            else:
                print(f"  ✗ Logistic Regression: Not loaded")
            
            # SVC with custom threshold
            if model_2_2_svc:
                try:
                    prediction = predict_with_threshold(
                        model_2_2_svc,
                        scaled_features,
                        threshold_2_2 if threshold_2_2 else 0.5,
                        "SVC"
                    )
                    if prediction is not None:
                        all_votes.append(prediction)
                        status = "🚨 Phishing" if prediction == 1 else "✅ Legitimate"
                        print(f"  ✓ SVC: {status}")
                except Exception as e:
                    print(f"  ✗ SVC error: {e}")
            else:
                print(f"  ✗ SVC: Not loaded")
                
        except Exception as e:
            print(f"  ✗ Team 2 error: {e}")
    else:
        print(f"  ✗ StandardScaler: Not loaded")

    # --- 3. Team 3 voting (Combined Features) ---
    print(f"\n{'─'*60}")
    print("🔗 Team 3: Combined Features Models Predictions")
    print(f"{'─'*60}")
    
    if vectorizer_team3 and scaler_team3:
        try:
            # Extract and transform features
            from .feature_extractor import transform_text_features
            text_features_raw = url.lower()
            features_t3_text = vectorizer_team3.transform([text_features_raw])
            features_t3_num = scaler_team3.transform(numerical_features_df)
            
            # Combine features
            combined_features = hstack([features_t3_text, features_t3_num]).tocsr()
            print(f"  ℹ️ Combined features shape: {combined_features.shape}")
            
            # XGBoost
            if model_3_1_xgb:
                try:
                    prediction = predict_with_threshold(
                        model_3_1_xgb,
                        combined_features,
                        threshold_3_1 if threshold_3_1 else 0.5,
                        "XGBoost"
                    )
                    if prediction is not None:
                        all_votes.append(prediction)
                        status = "🚨 Phishing" if prediction == 1 else "✅ Legitimate"
                        print(f"  ✓ XGBoost: {status}")
                except Exception as e:
                    print(f"  ✗ XGBoost error: {e}")
            else:
                print(f"  ✗ XGBoost: Not loaded")
            
            # Neural Network (MLP)
            if model_3_2_mlp:
                try:
                    prediction = predict_with_threshold(
                        model_3_2_mlp,
                        combined_features,
                        threshold_3_2 if threshold_3_2 else 0.5,
                        "Neural Network"
                    )
                    if prediction is not None:
                        all_votes.append(prediction)
                        status = "🚨 Phishing" if prediction == 1 else "✅ Legitimate"
                        print(f"  ✓ Neural Network: {status}")
                except Exception as e:
                    print(f"  ✗ Neural Network error: {e}")
            else:
                print(f"  ✗ Neural Network: Not loaded")
                
        except Exception as e:
            print(f"  ✗ Team 3 error: {e}")
    else:
        print(f"  ✗ Vectorizer or Scaler: Not loaded")

    # --- 4. Check for available votes ---
    if not all_votes:
        print(f"\n{'='*60}")
        print("❌ ERROR: No models available for prediction!")
        print(f"{'='*60}")
        return "Error: No models available for prediction"
    
    # --- 5. Final voting process ---
    print(f"\n{'='*60}")
    print("🗳️ VOTING RESULTS")
    print(f"{'='*60}")
    
    vote_counts = Counter(all_votes)
    total_votes = len(all_votes)
    legitimate_votes = vote_counts.get(0, 0)
    phishing_votes = vote_counts.get(1, 0)
    
    legitimate_percentage = (legitimate_votes / total_votes) * 100
    phishing_percentage = (phishing_votes / total_votes) * 100
    
    print(f"\n📊 Vote Distribution:")
    print(f"  • Total models voted: {total_votes}")
    print(f"  • Legitimate votes: {legitimate_votes} ({legitimate_percentage:.1f}%)")
    print(f"  • Phishing votes: {phishing_votes} ({phishing_percentage:.1f}%)")
    print(f"  • Raw votes: {all_votes}")
    
    # Determine final result: majority wins, with tie-breaker (Phishing for safety)
    if phishing_votes > legitimate_votes:
        final_result = 1
    elif legitimate_votes > phishing_votes:
        final_result = 0
    else:
        # Tie: prefer Phishing for safety
        print(f"\n⚖️ Tie detected! Defaulting to Phishing for safety.")
        final_result = 1
    
    final_decision = "Phishing" if final_result == 1 else "Legitimate"
    confidence = max(legitimate_percentage, phishing_percentage)
    
    print(f"\n{'='*60}")
    if final_result == 1:
        print(f"🚨 FINAL DECISION: {final_decision}")
    else:
        print(f"✅ FINAL DECISION: {final_decision}")
    print(f"📈 Confidence: {confidence:.1f}%")
    print(f"{'='*60}\n")
    
    return final_decision


def get_models_status():
    """
    Return the loading status of all models in an organized manner.
    
    This function provides a comprehensive overview of which models
    are loaded and ready for making predictions, useful for system
    monitoring and debugging.
    
    Returns:
        dict: Dictionary containing the status of all models organized by team
    """
    models_status = {
        'Team 1': {
            'Random Forest': model_1_1_rf is not None,
            'LightGBM': model_1_2_lgbm is not None
        },
        'Team 2': {
            'Logistic Regression': model_2_1_lr is not None,
            'SVC': model_2_2_svc is not None,
            'StandardScaler': scaler_team2 is not None
        },
        'Team 3': {
            'XGBoost': model_3_1_xgb is not None,
            'Neural Network': model_3_2_mlp is not None,
            'TF-IDF Vectorizer': vectorizer_team3 is not None,
            'Scaler': scaler_team3 is not None
        }
    }
    
    # Calculate statistics
    total_count = 0
    loaded_count = 0
    
    print(f"\n{'='*60}")
    print("📦 MODELS LOADING STATUS")
    print(f"{'='*60}\n")
    
    for team, models in models_status.items():
        print(f"{team}:")
        for model_name, status in models.items():
            total_count += 1
            if status:
                loaded_count += 1
            status_icon = "✅" if status else "❌"
            print(f"  {status_icon} {model_name}")
        print()
    
    print(f"{'─'*60}")
    print(f"Summary: {loaded_count}/{total_count} components loaded successfully")
    
    if loaded_count == total_count:
        print("✅ All models loaded successfully!")
    elif loaded_count == 0:
        print("❌ No models loaded! System will not work.")
    else:
        print(f"⚠️ Warning: Only {loaded_count}/{total_count} models loaded.")
    
    print(f"{'='*60}\n")
    
    return models_status


# Load model status when importing the file
if __name__ != "__main__":
    get_models_status()