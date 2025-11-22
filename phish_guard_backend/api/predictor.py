# api/predictor.py
# Machine Learning Prediction Engine for Phish-Guard
# Enhanced merged version combining both implementations

"""
═══════════════════════════════════════════════════════════════════════════════
SYSTEM ARCHITECTURE - Multi-Level Detection System
═══════════════════════════════════════════════════════════════════════════════

📋 LEVEL 1: Whitelist Check
   - Check if domain is in trusted whitelist (e.g., google.com, facebook.com)
   - If trusted → Return "Legitimate" immediately (no further analysis)

🤖 LEVEL 2: AI Models Voting (6 Models)
   - Team 1 (Numerical - 9 features):
     • Random Forest
     • LightGBM
   - Team 2 (Numerical Scaled - 9 features):
     • Logistic Regression
     • SVC (Support Vector Classifier)
   - Team 3 (Combined TF-IDF + Numerical - ~10009 features):
     • XGBoost
     • Neural Network (MLP)
   - Each model votes: 0 = Legitimate, 1 = Phishing
   - Majority vote determines preliminary verdict

🔍 LEVEL 3: HTML Content Analysis (ONLY if models vote Phishing)
   - If models vote "Legitimate" → Return "Legitimate" (skip Level 3)
   - If models vote "Phishing" → Perform HTML analysis:
     • Check for password input fields
     • Verify forms sending data to external domains
     • Detect sensitive keywords (credit card, SSN, etc.)
   - HTML Analysis Results:
     • If suspicious content found → Confirm "Phishing"
     • If content is clean → Override to "Legitimate" (False Positive)

FINAL OUTPUT: Verdict + Detailed Reason + Model Votes + HTML Analysis
═══════════════════════════════════════════════════════════════════════════════
"""

import os
from collections import Counter
import pandas as pd
import numpy as np
from urllib.parse import urlparse

# Import joblib with fallback
try:
    import joblib
    from scipy.sparse import hstack
    JOBLIB_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Required ML libraries not installed ({e}). Using fallback prediction.")
    JOBLIB_AVAILABLE = False

# Import feature extraction modules
from .feature_extractor import (
    extract_numerical_features, 
    transform_text_features,
    validate_url,
    PhishingFeatureExtractor
)
from .html_analyzer import inspect_page_content

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'ml_model')

# Whitelist - Trusted Domains (Level 1)
TRUSTED_DOMAINS = {
    # Global platforms
    'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'office.com',
    'live.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'amazon.com',
    'apple.com', 'linkedin.com', 'x.com', 'twitter.com', 'github.com', 
    'wikipedia.org', 'chatgpt.com', 'openai.com', 'claude.ai', 'stackoverflow.com',
    # Egyptian domains
    'te.eg', 'nbe.com.eg', 'cib.com.eg', 'banquemisr.com',
    'vodafone.eg', 'orange.eg', 'etisalat.eg', 'gov.eg'
}

# Feature column names for different teams
NUMERICAL_FEATURES_TEAM1 = [
    'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
    'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
]

NUMERICAL_FEATURES_TEAM2 = [
    'UrlLength', 'HostnameLength', 'NumDots', 'NumDash', 'AtSymbol',
    'NumQueryComponents', 'PathLength', 'NumNumericChars', 'NoHttps'
]

NUMERICAL_FEATURES_TEAM3 = [
    'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
    'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
]

# Label mapping for normalization
LABEL_TO_INT = {
    'phishing': 1, 'malicious': 1, 'spam': 1, 'unsafe': 1,
    'legitimate': 0, 'benign': 0, 'safe': 0, 'clean': 0,
}

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def load_tool(filename):
    """Load a model or tool from joblib file with error handling."""
    if not JOBLIB_AVAILABLE:
        return None, None
    
    try:
        path = os.path.join(MODEL_DIR, filename)
        if not os.path.exists(path):
            print(f"File not found: {path}")
            return None, None
            
        loaded_data = joblib.load(path)
        
        # Check if model is wrapped in dictionary
        if isinstance(loaded_data, dict) and 'model' in loaded_data:
            model = loaded_data['model']
            threshold = loaded_data.get('threshold', 0.5)
            feature_names = loaded_data.get('feature_names', None)
            
            if feature_names is not None:
                try:
                    n_features = len(feature_names)
                    print(f"✓ Loaded: {filename} ({n_features} features, threshold={threshold:.3f})")
                except:
                    print(f"✓ Loaded: {filename} (threshold={threshold:.3f})")
            else:
                print(f"✓ Loaded: {filename} (threshold={threshold:.3f})")
            
            return model, threshold
        else:
            # Model saved directly without wrapper
            print(f"✓ Loaded: {filename} (default threshold=0.5)")
            return loaded_data, 0.5
            
    except Exception as e:
        print(f"✗ Error loading {filename}: {e}")
        return None, None

def unwrap_scaler(scaler):
    """Extract scaler from dictionary wrapper if needed."""
    if scaler is None:
        return None
    if isinstance(scaler, dict):
        if 'scaler' in scaler:
            return scaler['scaler']
        elif 'model' in scaler:
            return scaler['model']
        else:
            for key, value in scaler.items():
                if hasattr(value, 'transform'):
                    return value
            return scaler
    return scaler

def normalize_prediction(raw_value, proba_threshold=0.5):
    """Normalize model outputs to 0 (Legitimate) or 1 (Phishing)."""
    # Unwrap arrays/lists
    if isinstance(raw_value, (list, tuple, np.ndarray)) and len(raw_value) > 0:
        raw_value = raw_value[0]

    # String labels mapping
    if isinstance(raw_value, str):
        label = raw_value.strip().lower()
        if label in LABEL_TO_INT:
            return LABEL_TO_INT[label]
        return 0  # Unknown strings default to legitimate

    # Booleans
    if isinstance(raw_value, bool):
        return 1 if raw_value else 0

    # Numeric types
    try:
        value = float(raw_value)
    except:
        return 0  # Unknown type -> conservative default

    # Probabilities in [0,1]
    if 0.0 <= value <= 1.0:
        return 1 if value >= proba_threshold else 0

    # Classification labels
    return 1 if value > 0 else 0

def predict_with_threshold(model, features, threshold, model_name):
    """Enhanced prediction function supporting predict_proba with custom threshold."""
    try:
        # Try predict_proba first for better threshold control
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(features)
            if proba.shape[1] == 2:  # Binary classification
                prediction = int(proba[0, 1] >= threshold)
                return prediction
        
        # Fallback to regular predict
        raw_pred = model.predict(features)[0]
        prediction = normalize_prediction(raw_pred, threshold)
        return prediction
        
    except Exception as e:
        print(f"  ✗ {model_name} error: {e}")
        return None

def check_whitelist(url):
    """Check if URL is in trusted domain whitelist."""
    try:
        hostname = urlparse(url).hostname
        if hostname:
            for trusted in TRUSTED_DOMAINS:
                if hostname == trusted or hostname.endswith('.' + trusted):
                    return True
    except:
        pass
    return False

def extract_team2_features(url):
    """Extract numerical features for Team 2 in correct order."""
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

# ═══════════════════════════════════════════════════════════════════════════
# MODEL LOADING
# ═══════════════════════════════════════════════════════════════════════════

print("Loading ML models...")

# Team 1: Numerical Models (9 features, no scaling)
model_1_1_rf, threshold_1_1 = load_tool('new_model_1_1_rf.joblib')
model_1_2_lgbm, threshold_1_2 = load_tool('new_model_1_2_lgbm.joblib')

# Team 2: Numerical Models with Scaler (9 features, scaled)
model_2_1_lr, threshold_2_1 = load_tool('new_model_2_1_lr.joblib')
model_2_2_svc, threshold_2_2 = load_tool('new_model_2_2_svc.joblib')
scaler_team2_raw, _ = load_tool('new_scaler_team2.joblib')
scaler_team2 = unwrap_scaler(scaler_team2_raw)

# Team 3: Combined Models (TF-IDF + Numerical, ~10009 features)
model_3_1_xgb, threshold_3_1 = load_tool('new_model_3_1_xgb.joblib')
model_3_2_mlp, threshold_3_2 = load_tool('new_model_3_2_mlp.joblib')
vectorizer_team3, _ = load_tool('new_tfidf_vectorizer_team3.joblib')
scaler_team3_raw, _ = load_tool('new_scaler_team3.joblib')
scaler_team3 = unwrap_scaler(scaler_team3_raw)

# ═══════════════════════════════════════════════════════════════════════════
# MAIN PREDICTION FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def make_final_prediction(url):
    """
    Main prediction function with 3-level analysis.
    
    Returns:
        dict: Complete analysis with verdict, reason, votes, and HTML analysis
    """
    print(f"\n{'='*70}")
    print(f"🔍 ANALYZING URL: {url}")
    print(f"{'='*70}")
    
    # ───────────────────────────────────────────────────────────────────────
    # LEVEL 1: Whitelist Check
    # ───────────────────────────────────────────────────────────────────────
    print(f"\n📋 LEVEL 1: Whitelist Check")
    if check_whitelist(url):
        hostname = urlparse(url).hostname
        print(f"✅ Domain '{hostname}' is in whitelist")
        print(f"{'='*70}\n")
        return {
            "verdict": "Legitimate",
            "reason": "Trusted Domain (Whitelist)",
            "model_votes": None,
            "html_analysis": None
        }
    print(f"ℹ️  Domain not in whitelist, proceeding to Level 2...")
    
    # ───────────────────────────────────────────────────────────────────────
    # LEVEL 2: AI Models Voting
    # ───────────────────────────────────────────────────────────────────────
    print(f"\n🤖 LEVEL 2: AI Models Voting")
    
    all_votes = []
    model_details = []
    
    # Extract features for Team 1
    extractor_t1 = PhishingFeatureExtractor()
    team1_df = extractor_t1.get_feature_dataframe(url)
    
    # Extract features for Team 3
    numerical_features_list = extract_numerical_features(url)
    numerical_features_df = pd.DataFrame([numerical_features_list], columns=NUMERICAL_FEATURES_TEAM3)
    
    # ──────────────────────────────────────────────────────────────────────
    # Team 1: Numerical Models (RF, LightGBM) - 9 features, no scaling
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n📊 Team 1: Numerical Models (9 features, no scaling):")
    
    if model_1_1_rf:
        pred = predict_with_threshold(model_1_1_rf, team1_df, threshold_1_1 or 0.5, "Random Forest")
        if pred is not None:
            all_votes.append(pred)
            model_details.append({
                "model": "Random Forest",
                "vote": int(pred),
                "label": "Phishing" if pred == 1 else "Legitimate",
                "type": "numerical"
            })
            print(f"    {'🚨' if pred == 1 else '✅'} Random Forest: {model_details[-1]['label']}")
    
    if model_1_2_lgbm:
        pred = predict_with_threshold(model_1_2_lgbm, team1_df, threshold_1_2 or 0.5, "LightGBM")
        if pred is not None:
            all_votes.append(pred)
            model_details.append({
                "model": "LightGBM",
                "vote": int(pred),
                "label": "Phishing" if pred == 1 else "Legitimate",
                "type": "numerical"
            })
            print(f"    {'🚨' if pred == 1 else '✅'} LightGBM: {model_details[-1]['label']}")
    
    # ──────────────────────────────────────────────────────────────────────
    # Team 2: Numerical Models with Scaler (LR, SVC) - 9 features, scaled
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n📊 Team 2: Numerical Models with Scaler (9 features, scaled):")
    
    if scaler_team2:
        try:
            team2_features = extract_team2_features(url)
            team2_features_df = pd.DataFrame([team2_features], columns=NUMERICAL_FEATURES_TEAM2)
            scaled_features = scaler_team2.transform(team2_features_df)
            
            if model_2_1_lr:
                pred = predict_with_threshold(model_2_1_lr, scaled_features, threshold_2_1 or 0.5, "Logistic Regression")
                if pred is not None:
                    all_votes.append(pred)
                    model_details.append({
                        "model": "Logistic Regression",
                        "vote": int(pred),
                        "label": "Phishing" if pred == 1 else "Legitimate",
                        "type": "numerical_scaled"
                    })
                    print(f"    {'🚨' if pred == 1 else '✅'} Logistic Regression: {model_details[-1]['label']}")
            
            if model_2_2_svc:
                pred = predict_with_threshold(model_2_2_svc, scaled_features, threshold_2_2 or 0.5, "SVC")
                if pred is not None:
                    all_votes.append(pred)
                    model_details.append({
                        "model": "SVC",
                        "vote": int(pred),
                        "label": "Phishing" if pred == 1 else "Legitimate",
                        "type": "numerical_scaled"
                    })
                    print(f"    {'🚨' if pred == 1 else '✅'} SVC: {model_details[-1]['label']}")
        except Exception as e:
            print(f"  ✗ Team 2 error: {e}")
    else:
        print(f"  ⚠️  Team 2 Scaler not available")
    
    # ──────────────────────────────────────────────────────────────────────
    # Team 3: Combined Models (XGBoost, MLP) - TF-IDF + Numerical
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n📊 Team 3: Combined Models (TF-IDF + Numerical ~10009 features):")
    
    if vectorizer_team3 and scaler_team3:
        try:
            text_features_raw = url.lower()
            features_t3_text = vectorizer_team3.transform([text_features_raw])
            features_t3_num = scaler_team3.transform(numerical_features_df)
            combined_features = hstack([features_t3_text, features_t3_num]).tocsr()
            
            print(f"  ℹ️  Combined features shape: {combined_features.shape}")
            
            if model_3_1_xgb:
                pred = predict_with_threshold(model_3_1_xgb, combined_features, threshold_3_1 or 0.5, "XGBoost")
                if pred is not None:
                    all_votes.append(pred)
                    model_details.append({
                        "model": "XGBoost",
                        "vote": int(pred),
                        "label": "Phishing" if pred == 1 else "Legitimate",
                        "type": "combined"
                    })
                    print(f"    {'🚨' if pred == 1 else '✅'} XGBoost: {model_details[-1]['label']}")
            
            if model_3_2_mlp:
                pred = predict_with_threshold(model_3_2_mlp, combined_features, threshold_3_2 or 0.5, "Neural Network")
                if pred is not None:
                    all_votes.append(pred)
                    model_details.append({
                        "model": "Neural Network (MLP)",
                        "vote": int(pred),
                        "label": "Phishing" if pred == 1 else "Legitimate",
                        "type": "combined"
                    })
                    print(f"    {'🚨' if pred == 1 else '✅'} Neural Network: {model_details[-1]['label']}")
        except Exception as e:
            print(f"  ✗ Team 3 error: {e}")
    else:
        print(f"  ⚠️  Team 3 Vectorizer or Scaler not available")
    
    # ───────────────────────────────────────────────────────────────────────
    # Check if we have any votes
    # ───────────────────────────────────────────────────────────────────────
    if not all_votes:
        print(f"\n❌ No votes received from models!")
        print(f"{'='*70}\n")
        return {
            "verdict": "Phishing",
            "reason": "Model prediction error - defaulting to Phishing for safety",
            "model_votes": None,
            "html_analysis": None
        }
    
    # ───────────────────────────────────────────────────────────────────────
    # Calculate voting results
    # ───────────────────────────────────────────────────────────────────────
    vote_counts = Counter(all_votes)
    total_votes = len(all_votes)
    legitimate_votes = vote_counts.get(0, 0)
    phishing_votes = vote_counts.get(1, 0)
    
    legitimate_pct = (legitimate_votes / total_votes * 100) if total_votes > 0 else 0
    phishing_pct = (phishing_votes / total_votes * 100) if total_votes > 0 else 0
    
    # Determine verdict (tie defaults to Phishing for safety)
    if phishing_votes > legitimate_votes:
        verdict = 1
    elif legitimate_votes > phishing_votes:
        verdict = 0
    else:
        verdict = 1  # Tie: default to Phishing
    
    voting_summary = {
        "total_votes": total_votes,
        "legitimate_votes": legitimate_votes,
        "phishing_votes": phishing_votes,
        "legitimate_percentage": round(legitimate_pct, 1),
        "phishing_percentage": round(phishing_pct, 1),
        "models_verdict": "Phishing" if verdict == 1 else "Legitimate",
        "detailed_votes": model_details
    }
    
    print(f"\n🗳️  VOTING RESULTS:")
    print(f"  ✅ Legitimate: {legitimate_votes}/{total_votes} ({legitimate_pct:.1f}%)")
    print(f"  🚨 Phishing: {phishing_votes}/{total_votes} ({phishing_pct:.1f}%)")
    print(f"  🎯 Models Verdict: {voting_summary['models_verdict']}")
    
    # ───────────────────────────────────────────────────────────────────────
    # DECISION POINT: Do we need Level 3?
    # ───────────────────────────────────────────────────────────────────────
    if verdict == 0:
        print(f"\n✅ Models voted LEGITIMATE - Skipping HTML analysis")
        print(f"{'='*70}\n")
        return {
            "verdict": "Legitimate",
            "reason": "AI models confirmed URL is safe",
            "model_votes": voting_summary,
            "html_analysis": None
        }
    
    # ───────────────────────────────────────────────────────────────────────
    # LEVEL 3: HTML Content Analysis
    # ───────────────────────────────────────────────────────────────────────
    print(f"\n🔎 LEVEL 3: HTML Content Analysis")
    print(f"⚠️  Models flagged URL as suspicious - Performing deep analysis...")
    
    html_analysis = inspect_page_content(url)
    
    if html_analysis.get("suspicious", False):
        evidence = html_analysis.get("evidence", [])
        score = html_analysis.get("score", 0)
        evidence_str = ", ".join(evidence) if evidence else "Suspicious content detected"
        
        print(f"🚨 HTML Analysis CONFIRMED suspicions!")
        print(f"  📊 Suspicion Score: {score}/100")
        print(f"  🔍 Evidence: {evidence_str}")
        print(f"\n❌ FINAL VERDICT: PHISHING")
        print(f"{'='*70}\n")
        
        return {
            "verdict": "Phishing",
            "reason": f"AI models + HTML evidence: {evidence_str}",
            "model_votes": voting_summary,
            "html_analysis": {
                "suspicious": True,
                "evidence": evidence,
                "score": score
            }
        }
    else:
        print(f"✅ HTML Analysis found NO threats!")
        print(f"  ℹ️  Page content appears safe")
        print(f"  🔄 Overriding model prediction (False Positive)")
        print(f"\n✅ FINAL VERDICT: LEGITIMATE")
        print(f"{'='*70}\n")
        
        return {
            "verdict": "Legitimate",
            "reason": "AI flagged as suspicious, but HTML content is clean (False Positive)",
            "model_votes": voting_summary,
            "html_analysis": {
                "suspicious": False,
                "evidence": [],
                "score": 0
            }
        }

# ═══════════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY WRAPPER
# ═══════════════════════════════════════════════════════════════════════════

def make_prediction(url, metadata=None):
    """
    Backward compatibility wrapper - returns simple string verdict.
    
    Args:
        url (str): URL to analyze
        metadata (dict): Optional metadata (not used)
        
    Returns:
        str: "Phishing" or "Legitimate"
    """
    if not JOBLIB_AVAILABLE:
        return "Phishing"  # Default to safe option
    
    if not validate_url(url):
        print(f"Invalid URL format: {url}")
        return "Error: Invalid URL format"
    
    result = make_final_prediction(url)
    return result.get("verdict", "Legitimate")

# ═══════════════════════════════════════════════════════════════════════════
# MODEL STATUS
# ═══════════════════════════════════════════════════════════════════════════

def get_models_status():
    """Return loading status of all models."""
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
    print(f"Summary: {loaded_count}/{total_count} components loaded")
    
    if loaded_count == total_count:
        print("✅ All models loaded successfully!")
    elif loaded_count == 0:
        print("❌ No models loaded! System will not work.")
    else:
        print(f"⚠️ Warning: Only {loaded_count}/{total_count} models loaded.")
    
    print(f"{'='*60}\n")
    
    return models_status

# Display model status on import
if __name__ != "__main__":
    get_models_status()