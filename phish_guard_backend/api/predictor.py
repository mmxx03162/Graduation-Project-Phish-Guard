import os
from collections import Counter
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Import joblib with fallback
try:
    import joblib
    import sklearn
    JOBLIB_AVAILABLE = True
    SKLEARN_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Required ML libraries not installed ({e}). Using fallback prediction.")
    JOBLIB_AVAILABLE = False
    SKLEARN_AVAILABLE = False

# --- استدعاء وحدة التحاليل ---
from .feature_extractor import (
    validate_url,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'ml_model')

# --- قائمة بأسماء الميزات الرقمية للفريق الأول ---
NUMERICAL_FEATURE_NAMES = [
    'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
    'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
]

LABEL_TO_INT = {
    # phishing-like
    'phishing': 1,
    'malicious': 1,
    'spam': 1,
    'unsafe': 1,
    # legitimate-like
    'legitimate': 0,
    'benign': 0,
    'safe': 0,
    'clean': 0,
}

def extract_team2_features(url):
    """
    استخراج الميزات الرقمية للفريق الثاني بالترتيب الصحيح
    حسب كود التدريب: ['UrlLength', 'HostnameLength', 'NumDots', 'NumDash', 
                      'AtSymbol', 'NumQueryComponents', 'PathLength', 'NumNumericChars', 'NoHttps']
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
    """Normalize model outputs to 0 (Legitimate) or 1 (Phishing).

    Handles:
      - Integer/boolean labels {0,1} or {-1,1}
      - Floats as probabilities in [0,1]
      - Strings like "phishing"/"legitimate"
    """
    # Unwrap arrays/lists
    if isinstance(raw_value, (list, tuple, np.ndarray)) and len(raw_value) > 0:
        raw_value = raw_value[0]

    # Strings labels mapping
    if isinstance(raw_value, str):
        label = raw_value.strip().lower()
        if label in LABEL_TO_INT:
            return LABEL_TO_INT[label]
        # Unknown strings default to legitimate to avoid unsafe bias
        return 0

    # Booleans
    if isinstance(raw_value, bool):
        return 1 if raw_value else 0

    # Numeric types
    try:
        value = float(raw_value)
    except Exception:
        # Unknown type -> conservative default: Legitimate (0)
        return 0

    # Probabilities in [0,1]
    if 0.0 <= value <= 1.0:
        return 1 if value >= proba_threshold else 0

    # Classification labels where <=0 is legitimate, >0 phishing
    return 1 if value > 0 else 0

def load_model(filename):
    """دالة مساعدة لتحميل الموديلات وتجنب تكرار الكود."""
    if not JOBLIB_AVAILABLE or not SKLEARN_AVAILABLE:
        print(f"Cannot load {filename}: Required ML libraries not available")
        return None, None
       
    try:
        path = os.path.join(MODEL_DIR, filename)
        if os.path.exists(path):
            loaded_data = joblib.load(path)
            
            # التحقق إذا كان الموديل محفوظ في dictionary
            if isinstance(loaded_data, dict) and 'model' in loaded_data:
                # استخراج الموديل والـ threshold من الـ dictionary
                model = loaded_data['model']
                threshold = loaded_data.get('threshold', 0.5)
                feature_names = loaded_data.get('feature_names', None)

                # طباعة معلومات إضافية (آمن مع numpy arrays)
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
                # الموديل محفوظ مباشرة بدون dictionary
                print(f"Successfully loaded: {filename} (using default threshold=0.5)")
                return loaded_data, 0.5
        else:
            print(f"File not found: {path}")
            return None, None
    except Exception as e:
        print(f"Error loading {filename}: {e}")
        return None, None

# --- تحميل جميع الموديلات ---
print("Loading all models...")

# تحميل موديلات الفريق الأول (Team 1 - Numerical Features)
model_1_1_rf, threshold_1_1 = load_model('new_model_1_1_rf.joblib')
model_1_2_lgbm, threshold_1_2 = load_model('new_model_1_2_lgbm.joblib')

# تحميل موديلات وأدوات الفريق الثاني (Team 2 - Numerical Features)
model_2_1_lr, threshold_2_1 = load_model('new_model_2_1_lr.joblib')
model_2_2_svc, threshold_2_2 = load_model('new_model_2_2_svc.joblib')
scaler_team2, _ = load_model('new_scaler_team2.joblib')  # StandardScaler للفريق الثاني

# تحميل موديلات وأدوات الفريق الثالث (Team 3 - Combined Features)
model_3_1_xgb, threshold_3_1 = load_model('new_model_3_1_xgb.joblib')
model_3_2_mlp, threshold_3_2 = load_model('new_model_3_2_mlp.joblib')
vectorizer_team3, _ = load_model('new_tfidf_vectorizer_team3.joblib')
scaler_team3, _ = load_model('new_scaler_team3.joblib')

# تقسيم الموديلات حسب النوع
numerical_models = {
    'Random Forest': model_1_1_rf,
    'LightGBM': model_1_2_lgbm,
    'XGBoost': model_3_1_xgb,
    'Neural Network': model_3_2_mlp
}

def predict_with_threshold(model, features, threshold, model_name):
    """
    دالة محسّنة للتنبؤ مع threshold مخصص - تدعم predict و predict_proba
    """
    try:
        # محاولة استخدام predict_proba للحصول على احتماليات
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(features)
            if proba.shape[1] == 2:  # Binary classification
                # استخدام الـ threshold المخصص
                prediction = int(proba[0, 1] >= threshold)
                return prediction
        
        # Fallback: استخدام predict العادي مع normalize_prediction
        raw_pred = model.predict(features)[0]
        prediction = normalize_prediction(raw_pred, threshold)
        return prediction
        
    except Exception as e:
        print(f"  ✗ {model_name} error: {e}")
        return None


def make_prediction(url: str, metadata: dict = None) -> str:
    """
    الدالة الرئيسية التي تدير عملية التصويت بين كل الخبراء الستة.
    
    Args:
        url: الرابط المراد فحصه
        metadata: بيانات إضافية اختيارية
    
    Returns:
        str: "Phishing" أو "Legitimate"
    """
    # Fallback prediction if required libraries not available
    if not JOBLIB_AVAILABLE or not SKLEARN_AVAILABLE:
        return "Phishing"  # Default to safe option
    
    # التحقق من صحة الـ URL
    if not validate_url(url):
        print(f"Invalid URL format: {url}")
        return "Error: Invalid URL format"
    
    if metadata is None:
        metadata = {}
    
    all_votes = []
    
    print(f"\n{'='*60}")
    print(f"🔍 Analyzing URL: {url}")
    print(f"{'='*60}")
    
    # --- استخراج الميزات الرقمية ---
    print("\n📊 Extracting numerical features...")
    
    # ميزات الفريق الأول (Team 1)
    from .feature_extractor import PhishingFeatureExtractor
    extractor_t1 = PhishingFeatureExtractor()
    team1_df = extractor_t1.get_feature_dataframe(url)

    # ميزات الفريق الثالث (Team 3) - ميزات رقمية مبسطة
    from .feature_extractor import extract_numerical_features
    numerical_features_list = extract_numerical_features(url)
    numerical_features_df = pd.DataFrame([numerical_features_list], columns=NUMERICAL_FEATURE_NAMES)
    print(f"✓ Extracted {len(numerical_features_list)} numerical features")
    
    # --- 1. تصويت الخبراء الرقميين (Team 1 + جزء من Team 3) ---
    print(f"\n{'─'*60}")
    print("🤖 Team 1: Numerical Models Predictions")
    print(f"{'─'*60}")
    
    # Random Forest
    if model_1_1_rf:
        try:
            # استخدام DataFrame مطابق لأسماء التدريب الخاصة بالموديل
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
            # بعض إصدارات LightGBM لا تتحقق من أسماء الأعمدة، لكن نمرر نفس team1_df لضمان الاتساق
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

    # --- 2. تصويت خبراء الميزات الرقمية (Team 2) ---
    print(f"\n{'─'*60}")
    print("📊 Team 2: Numerical Features Models Predictions")
    print(f"{'─'*60}")
    
    if scaler_team2:
        try:
            # استخراج الميزات الرقمية للفريق الثاني
            team2_features = extract_team2_features(url)
            team2_features_df = pd.DataFrame([team2_features], columns=[
                'UrlLength', 'HostnameLength', 'NumDots', 'NumDash', 'AtSymbol',
                'NumQueryComponents', 'PathLength', 'NumNumericChars', 'NoHttps'
            ])
            
            # تطبيق StandardScaler
            scaled_features = scaler_team2.transform(team2_features_df)
            
            # Logistic Regression مع threshold مخصص
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
            
            # SVC مع threshold مخصص
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

    # --- 3. تصويت الفريق الثالث (Combined Features) ---
    print(f"\n{'─'*60}")
    print("🔗 Team 3: Combined Features Models Predictions")
    print(f"{'─'*60}")
    
    if vectorizer_team3 and scaler_team3:
        try:
            # استخراج وتحويل الميزات
            from .feature_extractor import transform_text_features
            text_features_raw = url.lower()
            features_t3_text = vectorizer_team3.transform([text_features_raw])
            features_t3_num = scaler_team3.transform(numerical_features_df)
            
            # دمج الميزات
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

    # --- 4. التحقق من وجود أصوات ---
    if not all_votes:
        print(f"\n{'='*60}")
        print("❌ ERROR: No models available for prediction!")
        print(f"{'='*60}")
        return "Error: No models available for prediction"
    
    # --- 5. عملية التصويت النهائية ---
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
    
    # تحديد النتيجة النهائية: الأغلبية تفوز، مع قاعدة التعادل (Phishing للأمان)
    if phishing_votes > legitimate_votes:
        final_result = 1
    elif legitimate_votes > phishing_votes:
        final_result = 0
    else:
        # التعادل: نفضل Phishing للأمان
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
    """إرجاع حالة تحميل كل الموديلات بشكل منظم"""
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
    
    # حساب الإحصائيات
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


# تحميل حالة الموديلات عند استيراد الملف
if __name__ != "__main__":
    get_models_status()