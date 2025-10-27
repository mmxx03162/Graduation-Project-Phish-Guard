"""
🔍 Feature Extractor - Matches Actual Dataset Columns
====================================================
Extract the 9 features with the same names that the models were trained on
"""

import re
from urllib.parse import urlparse
import socket
import ssl
import requests
from datetime import datetime

class PhishingFeatureExtractor:
    """
    Extract the 9 features matching the original dataset columns.
    
    This class provides methods to extract various features from URLs
    that are used by machine learning models to detect phishing attempts.
    The features are designed to match the original dataset structure
    used during model training.
    """
    
    def __init__(self):
        """
        Initialize the feature extractor with the expected feature names.
        
        These feature names must match exactly with the training dataset
        to ensure proper model compatibility.
        """
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
        Extract all 9 features from a given URL.
        
        This method performs comprehensive analysis of the URL to extract
        various characteristics that can indicate phishing behavior.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Dictionary containing feature names and their values
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            
            # 1. URLURL_Length (URL length)
            features['URLURL_Length'] = len(url)
            
            # 2. having_At_Symbol (presence of @ symbol)
            features['having_At_Symbol'] = 1 if '@' in url else -1
            
            # 3. Prefix_Suffix (presence of - in domain)
            features['Prefix_Suffix'] = 1 if '-' in domain else -1
            
            # 4. having_Sub_Domain (number of dots = number of subdomains)
            dot_count = domain.count('.')
            if dot_count == 0:
                features['having_Sub_Domain'] = 1
            elif dot_count == 1:
                features['having_Sub_Domain'] = -1
            elif dot_count == 2:
                features['having_Sub_Domain'] = 0
            else:
                features['having_Sub_Domain'] = 1
            
            # 5. SSLfinal_State (SSL certificate status)
            features['SSLfinal_State'] = self._check_ssl(url)
            
            # 6. Domain_registeration_length (registration duration - estimate)
            # -1: long, 0: medium, 1: short
            features['Domain_registeration_length'] = self._estimate_domain_registration(domain)
            
            # 7. age_of_domain (domain age - estimate)
            # -1: old, 0: medium, 1: new
            features['age_of_domain'] = self._estimate_domain_age(domain)
            
            # 8. DNSRecord (presence of DNS record)
            features['DNSRecord'] = self._check_dns(domain)
            
            # 9. Page_Rank (website popularity estimate)
            # -1: popular, 0: medium, 1: not popular
            features['Page_Rank'] = self._estimate_page_rank(domain)
            
        except Exception as e:
            print(f"⚠️ Error extracting features: {e}")
            # In case of error, return default values
            for name in self.feature_names:
                if name not in features:
                    features[name] = 0
        
        return features
    
    def _check_ssl(self, url):
        """
        Check SSL certificate status.
        
        This method attempts to verify if the URL has a valid SSL certificate
        by attempting to establish an SSL connection.
        
        Args:
            url (str): The URL to check
            
        Returns:
            int: SSL status (-1: valid SSL, 0: invalid SSL, 1: no HTTPS)
        """
        try:
            if url.startswith('https://'):
                parsed = urlparse(url)
                domain = parsed.netloc
                
                # Attempt SSL connection
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        # SSL exists and is valid
                        return -1
            else:
                # No HTTPS
                return 1
        except:
            # SSL invalid or error
            return 0
    
    def _estimate_domain_registration(self, domain):
        """
        Estimate domain registration duration.
        
        This method provides a heuristic estimate of how long a domain
        has been registered based on known popular domains.
        
        Args:
            domain (str): The domain to analyze
            
        Returns:
            int: Registration length (-1: long, 0: medium, 1: short)
        """
        # Popular domains usually have long registration periods
        famous_domains = ['google', 'facebook', 'youtube', 'amazon', 'wikipedia', 
                         'twitter', 'instagram', 'linkedin', 'microsoft', 'apple']
        
        if any(famous in domain.lower() for famous in famous_domains):
            return -1  # Long registration
        
        # Default: short registration (suspicious)
        return 1
    
    def _estimate_domain_age(self, domain):
        """
        Estimate domain age.
        
        This method provides a heuristic estimate of how old a domain is
        based on known popular domains and their typical age.
        
        Args:
            domain (str): The domain to analyze
            
        Returns:
            int: Domain age (-1: old, 0: medium, 1: new)
        """
        # Popular domains are usually old
        famous_domains = ['google', 'facebook', 'youtube', 'amazon', 'wikipedia',
                         'twitter', 'instagram', 'linkedin', 'microsoft', 'apple',
                         'yahoo', 'reddit', 'ebay', 'netflix', 'paypal']
        
        if any(famous in domain.lower() for famous in famous_domains):
            return -1  # Old domain
        
        # Default: new domain
        return 1
    
    def _check_dns(self, domain):
        """
        Check for DNS record existence.
        
        This method attempts to resolve the domain to check if it has
        a valid DNS record.
        
        Args:
            domain (str): The domain to check
            
        Returns:
            int: DNS status (-1: DNS exists, 1: DNS not found)
        """
        try:
            socket.gethostbyname(domain)
            return -1  # DNS exists
        except:
            return 1  # DNS not found
    
    def _estimate_page_rank(self, domain):
        """
        Estimate website popularity (Page Rank).
        
        This method provides a heuristic estimate of website popularity
        based on known popular domains and domain extensions.
        
        Args:
            domain (str): The domain to analyze
            
        Returns:
            int: Page rank estimate (-1: high, 0: medium, 1: low)
        """
        # List of very popular websites
        top_sites = ['google', 'youtube', 'facebook', 'amazon', 'wikipedia',
                    'yahoo', 'reddit', 'twitter', 'instagram', 'linkedin',
                    'netflix', 'microsoft', 'apple', 'ebay', 'cnn', 'bbc']
        
        domain_lower = domain.lower()
        
        # If it's from famous sites
        if any(site in domain_lower for site in top_sites):
            return -1  # High Page Rank
        
        # Medium popularity sites
        if any(ext in domain_lower for ext in ['.edu', '.gov', '.org']):
            return 0
        
        # Default: not popular website
        return 1
    
    def get_feature_vector(self, url):
        """
        Get a feature vector ready for prediction.
        
        This method returns the features as a list in the same order
        as the feature_names list, suitable for direct use with models.
        
        Args:
            url (str): The URL to extract features from
            
        Returns:
            list: List of feature values in the same order as feature_names
        """
        features_dict = self.extract_features(url)
        return [features_dict[name] for name in self.feature_names]
    
    def get_feature_dataframe(self, url):
        """
        Get a DataFrame ready for prediction.
        
        This method returns the features as a pandas DataFrame,
        which is the preferred format for many machine learning models.
        
        Args:
            url (str): The URL to extract features from
            
        Returns:
            pandas.DataFrame: DataFrame containing the extracted features
        """
        import pandas as pd
        features_dict = self.extract_features(url)
        return pd.DataFrame([features_dict])


# ═══════════════════════════════════════════════════════════
# ✅ Backward-compatible function API expected by predictor.py
# ═══════════════════════════════════════════════════════════

def validate_url(url):
    """
    Simple URL format validation.
    
    This function performs basic validation to ensure the URL
    has a proper format before processing.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if URL is valid, False otherwise
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        return True
    except Exception:
        return False


def extract_numerical_features(url):
    """
    Return a list of 9 numerical features in the order expected by predictor.NUMERICAL_FEATURE_NAMES.
    
    This function extracts numerical features that are used by the machine learning models.
    The features are returned in a specific order that matches the training data structure.
    
    Expected order:
    [
        'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
        'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
    ]
    
    Args:
        url (str): The URL to extract features from
        
    Returns:
        list: List of 9 numerical features in the expected order
    """
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path

    url_length = len(url)
    hostname_length = len(hostname)
    num_dots = hostname.count('.')
    uses_https = 1 if parsed.scheme.lower() == 'https' else 0

    # List of suspicious keywords commonly used in phishing URLs
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
        # Count of key=value pairs
        num_query_components = sum(1 for part in parsed.query.split('&') if part)

    # Estimate domain age (in days) approximately without whois
    famous_domains = [
        'google', 'facebook', 'youtube', 'amazon', 'wikipedia', 'yahoo', 'reddit',
        'twitter', 'instagram', 'linkedin', 'microsoft', 'apple', 'paypal', 'netflix'
    ]
    if any(fd in hostname.lower() for fd in famous_domains):
        domain_age_days = 3650  # ~10 years
    else:
        domain_age_days = 30  # Conservative estimate for new/suspicious domains

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
    """
    Transform text to TF-IDF features using the loaded vectorizer.
    
    This function converts raw text into TF-IDF features that can be used
    by machine learning models for text-based analysis.
    
    Args:
        text (str): The text to transform
        vectorizer: The TF-IDF vectorizer to use for transformation
        
    Returns:
        scipy.sparse matrix: Transformed text features or None if error
    """
    try:
        processed = (text or '').lower()
        return vectorizer.transform([processed])
    except Exception as e:
        print(f"Text transform error: {e}")
        return None


# The following functions are not directly used in predictor currently,
# but they are imported, so we provide lightweight compatible interfaces.
def extract_features_for_team1(url):
    """
    DataFrame with numerical features for Team 1.
    
    Args:
        url (str): The URL to extract features from
        
    Returns:
        pandas.DataFrame: DataFrame with numerical features
    """
    import pandas as pd
    cols = [
        'UrlLength', 'HostnameLength', 'NumDots', 'UsesHTTPS', 'HasSuspiciousKeyword',
        'NumDash', 'HasAtSymbol', 'NumQueryComponents', 'DomainAgeDays'
    ]
    values = extract_numerical_features(url)
    return pd.DataFrame([values], columns=cols)


def extract_features_for_team2(url, vectorizer):
    """
    Text feature matrix for Team 2.
    
    Args:
        url (str): The URL to extract features from
        vectorizer: The TF-IDF vectorizer to use
        
    Returns:
        scipy.sparse matrix: Transformed text features
    """
    return transform_text_features(url, vectorizer)


def extract_features_for_team3(url, vectorizer, scaler):
    """
    Combine TF-IDF + numerical features as CSR for Team 3.
    
    Args:
        url (str): The URL to extract features from
        vectorizer: The TF-IDF vectorizer to use
        scaler: The scaler to use for numerical features
        
    Returns:
        scipy.sparse matrix: Combined features or None if error
    """
    from scipy.sparse import hstack
    num_df = extract_features_for_team1(url)
    try:
        num_scaled = scaler.transform(num_df)
    except Exception:
        # If scaling fails for any reason, use values as they are
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
    
    # Create Extractor
    extractor = PhishingFeatureExtractor()
    
    # Test URLs
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
        
        # Extract Features
        features = extractor.extract_features(url)
        
        print("\n📊 Extracted Features:")
        for name, value in features.items():
            symbol = "✅" if value == -1 else ("⚠️" if value == 0 else "❌")
            print(f"   {symbol} {name:<30}: {value:>3}")
        
        # Get DataFrame
        df = extractor.get_feature_dataframe(url)
        print(f"\n📋 DataFrame shape: {df.shape}")
        print(f"   Columns: {list(df.columns)}")
        
        # Try loading and predicting
        try:
            model_data = joblib.load('ml_model/new_model_1_1_rf.joblib')
            model = model_data['model']
            
            print(f"\n🤖 Model Feature Names:")
            for i, name in enumerate(model_data['feature_names'], 1):
                print(f"   {i}. {name}")
            
            # Prediction
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