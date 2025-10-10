"""
🔍 Feature Extractor - يطابق أعمدة Dataset الفعلية
====================================================
استخراج الـ 9 features بنفس الأسماء اللي النماذج اتدربت عليها
"""

import re
from urllib.parse import urlparse
import socket
import ssl
import requests
from datetime import datetime

class PhishingFeatureExtractor:
    """
    استخراج الـ 9 features المطابقة لأعمدة dataset الأصلي
    """
    
    def __init__(self):
        self.feature_names = [
            'URLURL_Length',
            'having_At_Symbol',
            'Prefix_Suffix',
            'having_Sub_Domain',
            'SSLfinal_State',
            'Domain_registeration_length',
            'age_of_domain',
            'DNSRecord',
            'Page_Rank'
        ]
    
    def extract_features(self, url):
        """
        استخراج جميع الـ 9 features من URL
        
        Returns:
            dict: {feature_name: value, ...}
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            
            # 1. URLURL_Length (طول الـ URL)
            features['URLURL_Length'] = len(url)
            
            # 2. having_At_Symbol (وجود رمز @)
            features['having_At_Symbol'] = 1 if '@' in url else -1
            
            # 3. Prefix_Suffix (وجود - في الدومين)
            features['Prefix_Suffix'] = 1 if '-' in domain else -1
            
            # 4. having_Sub_Domain (عدد النقاط = عدد الـ subdomains)
            dot_count = domain.count('.')
            if dot_count == 0:
                features['having_Sub_Domain'] = 1
            elif dot_count == 1:
                features['having_Sub_Domain'] = -1
            elif dot_count == 2:
                features['having_Sub_Domain'] = 0
            else:
                features['having_Sub_Domain'] = 1
            
            # 5. SSLfinal_State (حالة SSL)
            features['SSLfinal_State'] = self._check_ssl(url)
            
            # 6. Domain_registeration_length (مدة التسجيل - تقدير)
            # -1: طويلة، 0: متوسطة، 1: قصيرة
            features['Domain_registeration_length'] = self._estimate_domain_registration(domain)
            
            # 7. age_of_domain (عمر الدومين - تقدير)
            # -1: قديم، 0: متوسط، 1: جديد
            features['age_of_domain'] = self._estimate_domain_age(domain)
            
            # 8. DNSRecord (وجود DNS record)
            features['DNSRecord'] = self._check_dns(domain)
            
            # 9. Page_Rank (تقدير شهرة الموقع)
            # -1: مشهور، 0: متوسط، 1: غير مشهور
            features['Page_Rank'] = self._estimate_page_rank(domain)
            
        except Exception as e:
            print(f"⚠️ Error extracting features: {e}")
            # في حالة الخطأ، نرجع قيم افتراضية
            for name in self.feature_names:
                if name not in features:
                    features[name] = 0
        
        return features
    
    def _check_ssl(self, url):
        """فحص SSL Certificate"""
        try:
            if url.startswith('https://'):
                parsed = urlparse(url)
                domain = parsed.netloc
                
                # محاولة الاتصال بـ SSL
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        # SSL موجود وصالح
                        return -1
            else:
                # لا يوجد HTTPS
                return 1
        except:
            # SSL غير صالح أو خطأ
            return 0
    
    def _estimate_domain_registration(self, domain):
        """تقدير مدة تسجيل الدومين"""
        # المواقع المشهورة عادة عندها تسجيل طويل
        famous_domains = ['google', 'facebook', 'youtube', 'amazon', 'wikipedia', 
                         'twitter', 'instagram', 'linkedin', 'microsoft', 'apple']
        
        if any(famous in domain.lower() for famous in famous_domains):
            return -1  # تسجيل طويل
        
        # افتراضي: تسجيل قصير (مشكوك فيه)
        return 1
    
    def _estimate_domain_age(self, domain):
        """تقدير عمر الدومين"""
        # المواقع المشهورة عادة قديمة
        famous_domains = ['google', 'facebook', 'youtube', 'amazon', 'wikipedia',
                         'twitter', 'instagram', 'linkedin', 'microsoft', 'apple',
                         'yahoo', 'reddit', 'ebay', 'netflix', 'paypal']
        
        if any(famous in domain.lower() for famous in famous_domains):
            return -1  # دومين قديم
        
        # افتراضي: دومين جديد
        return 1
    
    def _check_dns(self, domain):
        """فحص وجود DNS Record"""
        try:
            socket.gethostbyname(domain)
            return -1  # DNS موجود
        except:
            return 1  # DNS غير موجود
    
    def _estimate_page_rank(self, domain):
        """تقدير شهرة الموقع (Page Rank)"""
        # قائمة المواقع المشهورة جداً
        top_sites = ['google', 'youtube', 'facebook', 'amazon', 'wikipedia',
                    'yahoo', 'reddit', 'twitter', 'instagram', 'linkedin',
                    'netflix', 'microsoft', 'apple', 'ebay', 'cnn', 'bbc']
        
        domain_lower = domain.lower()
        
        # إذا كان من المواقع الشهيرة
        if any(site in domain_lower for site in top_sites):
            return -1  # Page Rank عالي
        
        # مواقع متوسطة الشهرة
        if any(ext in domain_lower for ext in ['.edu', '.gov', '.org']):
            return 0
        
        # افتراضي: موقع غير مشهور
        return 1
    
    def get_feature_vector(self, url):
        """
        الحصول على Feature Vector جاهز للتنبؤ
        
        Returns:
            list: قائمة القيم بنفس ترتيب feature_names
        """
        features_dict = self.extract_features(url)
        return [features_dict[name] for name in self.feature_names]
    
    def get_feature_dataframe(self, url):
        """
        الحصول على DataFrame جاهز للتنبؤ
        """
        import pandas as pd
        features_dict = self.extract_features(url)
        return pd.DataFrame([features_dict])


# ═══════════════════════════════════════════════════════════
# ✅ Backward-compatible function API expected by predictor.py
# ═══════════════════════════════════════════════════════════

def validate_url(url):
    """تحقق بسيط من تنسيق الرابط."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        return True
    except Exception:
        return False


def extract_numerical_features(url):
    """
    إرجاع قائمة تضم 9 ميزات رقمية بالترتيب المتوقع في predictor.NUMERICAL_FEATURE_NAMES:
    [
        'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
        'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
    ]
    """
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path

    url_length = len(url)
    hostname_length = len(hostname)
    num_dots = hostname.count('.')
    uses_https = 1 if parsed.scheme.lower() == 'https' else 0

    suspicious_keywords = [
        'login', 'verify', 'update', 'secure', 'account', 'bank', 'confirm', 'pay',
        'password', 'signin', 'support', 'help', 'billing'
    ]
    lower_url = url.lower()
    has_suspicious_kw = 1 if any(k in lower_url for k in suspicious_keywords) else 0

    num_dash = hostname.count('-')
    has_at_symbol = 1 if '@' in url else 0
    num_query_components = 0
    if parsed.query:
        # count of key=value pairs
        num_query_components = sum(1 for part in parsed.query.split('&') if part)

    # تقدير عمر الدومين (بالأيام) بشكل تقريبي بدون whois
    famous_domains = [
        'google', 'facebook', 'youtube', 'amazon', 'wikipedia', 'yahoo', 'reddit',
        'twitter', 'instagram', 'linkedin', 'microsoft', 'apple', 'paypal', 'netflix'
    ]
    if any(fd in hostname.lower() for fd in famous_domains):
        domain_age_days = 3650  # ~10 سنوات
    else:
        domain_age_days = 30  # تقدير محافظ للدومينات الجديدة/المشبوهة

    return [
        url_length,
        hostname_length,
        num_dots,
        uses_https,
        has_suspicious_kw,
        num_dash,
        has_at_symbol,
        num_query_components,
        domain_age_days,
    ]


def transform_text_features(text, vectorizer):
    """تحويل النص إلى ميزات TF-IDF باستخدام الـ vectorizer المحمل."""
    try:
        processed = (text or '').lower()
        return vectorizer.transform([processed])
    except Exception as e:
        print(f"Text transform error: {e}")
        return None


# الدوال التالية غير مستخدمة مباشرة في predictor حالياً،
# ولكن يتم استيرادها، لذا نوفر واجهات خفيفة متوافقة.
def extract_features_for_team1(url):
    """DataFrame بميزات رقمية للفريق 1."""
    import pandas as pd
    cols = [
        'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
        'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
    ]
    values = extract_numerical_features(url)
    return pd.DataFrame([values], columns=cols)


def extract_features_for_team2(url, vectorizer):
    """مصفوفة ميزات نصية للفريق 2."""
    return transform_text_features(url, vectorizer)


def extract_features_for_team3(url, vectorizer, scaler):
    """دمج ميزات TF-IDF + رقمية بشكل CSR للفريق 3."""
    from scipy.sparse import hstack
    num_df = extract_features_for_team1(url)
    try:
        num_scaled = scaler.transform(num_df)
    except Exception:
        # إذا تعذر التحجيم لأي سبب، استخدم القيم كما هي
        num_scaled = num_df.values
    text_features = transform_text_features(url, vectorizer)
    try:
        combined = hstack([text_features, num_scaled]).tocsr()
        return combined
    except Exception as e:
        print(f"Team3 combine error: {e}")
        return None

# ═══════════════════════════════════════════════════════════
# 🧪 TESTING
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import joblib
    import pandas as pd
    
    print("="*70)
    print("🔍 Testing Feature Extractor with Real Model")
    print("="*70)
    
    # إنشاء Extractor
    extractor = PhishingFeatureExtractor()
    
    # تجربة URLs
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com",
        "http://suspicious-website-12345.tk",
        "https://secure-paypal-verify.xyz"
    ]
    
    for url in test_urls:
        print(f"\n{'─'*70}")
        print(f"📍 URL: {url}")
        print(f"{'─'*70}")
        
        # استخراج Features
        features = extractor.extract_features(url)
        
        print("\n📊 Extracted Features:")
        for name, value in features.items():
            symbol = "✅" if value == -1 else ("⚠️" if value == 0 else "❌")
            print(f"   {symbol} {name:<30}: {value:>3}")
        
        # الحصول على DataFrame
        df = extractor.get_feature_dataframe(url)
        print(f"\n📋 DataFrame shape: {df.shape}")
        print(f"   Columns: {list(df.columns)}")
        
        # محاولة التحميل والتنبؤ
        try:
            model_data = joblib.load('ml_model/new_model_1_1_rf.joblib')
            model = model_data['model']
            
            print(f"\n🤖 Model Feature Names:")
            for i, name in enumerate(model_data['feature_names'], 1):
                print(f"   {i}. {name}")
            
            # التنبؤ
            prediction = model.predict(df)[0]
            proba = model.predict_proba(df)[0]
            
            result = "✅ Legitimate" if prediction <= 0 else "🚨 Phishing"
            confidence = max(proba) * 100
            
            print(f"\n🎯 Prediction: {result}")
            print(f"📊 Confidence: {confidence:.1f}%")
            
        except FileNotFoundError:
            print(f"\n⚠️ Model file not found. Train the model first!")
        except Exception as e:
            print(f"\n❌ Error during prediction: {e}")
    
    print(f"\n{'='*70}\n")