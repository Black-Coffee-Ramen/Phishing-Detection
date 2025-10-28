# src/features/lexical_features.py
import pandas as pd
import numpy as np
import re
import math
import idna  # for decoding Punycode safely
from urllib.parse import urlparse


CSE_KEYWORDS = [
    # Original
    'nic', 'crsorgi', 'irctc', 'sbi', 'icici', 'hdfc', 'pnb', 'bob', 'airtel', 'iocl',
    # Expanded
    'onlinesbi', 'sbicard', 'icicibank', 'hdfcbank', 'pnbindia', 'bankofbaroda',
    'airtel', 'irctc', 'rail', 'railway', 'gov.in', 'crsorgi', 'census'
]


def extract_url_features(df, domain_col='domain'):
    """Extract lexical features from domains"""
    domains = df[domain_col].astype(str)
    
    features = pd.DataFrame(index=df.index)
    
    # Basic length features
    features['domain_length'] = domains.str.len()
    features['num_digits'] = domains.str.count(r'\d')
    features['num_hyphens'] = domains.str.count('-')
    features['num_underscores'] = domains.str.count('_')  # This was missing
    features['num_dots'] = domains.str.count(r'\.')
    features['num_special_chars'] = domains.str.count(r'[^a-zA-Z0-9.-]')
    
    # Character composition ratios
    features['digit_ratio'] = features['num_digits'] / np.maximum(features['domain_length'], 1)
    features['hyphen_ratio'] = features['num_hyphens'] / np.maximum(features['domain_length'], 1)
    features['special_char_ratio'] = features['num_special_chars'] / np.maximum(features['domain_length'], 1)
    
    # Special patterns - FIXED to avoid regex warning
    features['has_ip'] = domains.str.match(r'^\d+\.\d+\.\d+\.\d+$').fillna(False).astype(int)
    
    # Fixed repeated digits detection
    repeated_digits_match = domains.str.extract(r'(\d)\1{2,}', expand=False)
    features['has_repeated_digits'] = (~repeated_digits_match.isna()).astype(int)
    
    # TLD features
    features['tld'] = domains.str.extract(r'\.([a-zA-Z]+)$', expand=False)
    features['is_common_tld'] = features['tld'].isin(['com', 'org', 'net', 'edu', 'gov']).fillna(False).astype(int)
    features['tld_length'] = features['tld'].str.len().fillna(0)
    
    # Entropy (measure of randomness)
    features['entropy'] = domains.apply(calculate_entropy)
    
    # Suspicious keywords
    suspicious_keywords = ['login', 'signin', 'secure', 'account', 'verify', 'update', 'support', 
                          'banking', 'paypal', 'auth', 'security', 'confirm']
    for keyword in suspicious_keywords:
        features[f'has_{keyword}'] = domains.str.contains(keyword, case=False, regex=False).fillna(False).astype(int)
    
    # Additional features
    features['has_https'] = domains.str.startswith('https://').fillna(False).astype(int)
    features['subdomain_count'] = domains.str.count(r'\.') - 1  # Subtract 1 for TLD dot
    
    # Fill NaN values and ensure proper types
    features = features.fillna(0)
    
    # Ensure all numeric types
    for col in features.columns:
        if features[col].dtype == 'object':
            features[col] = features[col].astype('category').cat.codes
        else:
            features[col] = features[col].astype(float)
    
    return pd.concat([df, features], axis=1)

def calculate_entropy(domain):
    """Calculate Shannon entropy of domain"""
    if len(domain) == 0:
        return 0
    entropy = 0
    for char in set(domain):
        p = domain.count(char) / len(domain)
        entropy -= p * np.log2(p) if p > 0 else 0
    return entropy