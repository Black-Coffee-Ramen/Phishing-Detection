# src/predict.py
import pandas as pd
import joblib
import numpy as np
import os
from src.features.lexical_features import extract_url_features
from src.features.whois_features import extract_whois_features

def identify_cse_target(domain):
    """
    Identify which CSE is being targeted by the domain
    Returns the CSE name and confidence level
    """
    domain_lower = domain.lower()
    
    # Define CSE patterns with their keywords
    cse_patterns = {
        'Indian Railway Catering and Tourism Corporation (IRCTC)': [
            'irctc', 'railway', 'indianrail', 'train', 'irctc.co'
        ],
        'State Bank of India (SBI)': [
            'sbi', 'statebank', 'sbicard', 'sbi.co', 'onlinesbi'
        ],
        'ICICI Bank': [
            'icici', 'icicibank', 'icicicard', 'icicisecurities'
        ],
        'HDFC Bank': [
            'hdfc', 'hdfcbank', 'hdfcsec', 'hdfclife'
        ],
        'Punjab National Bank (PNB)': [
            'pnb', 'punjabnational', 'pnbbank', 'pnbindia'
        ],
        'Bank of Baroda (BOB)': [
            'bob', 'bankofbaroda', 'bobcard', 'bobfinancial'
        ],
        'Airtel': [
            'airtel', 'bhartiairtel', 'airtel.in', 'airtelpayments'
        ],
        'Indian Oil (IOCL)': [
            'iocl', 'indianoil', 'ioclonline', 'ioclpetroleum'
        ],
        'National Informatics Centre (NIC)': [
            'nic', 'nic.in', 'india.gov', 'digitalindia'
        ],
        'CRS Org (CRSORG)': [
            'crsorg', 'crsorgi', 'crsindia', 'consular'
        ]
    }
    
    # Check for each CSE
    target_cses = []
    for cse_name, keywords in cse_patterns.items():
        for keyword in keywords:
            if keyword in domain_lower:
                target_cses.append(cse_name)
                break  # Found one match, move to next CSE
    
    if target_cses:
        # Return the most specific match (usually the first one found)
        return target_cses[0], 'High'
    else:
        # Check for generic banking/financial patterns
        generic_patterns = {
            'Financial Institution (Generic)': ['bank', 'credit', 'loan', 'card', 'insurance', 'mutual'],
            'Government Service (Generic)': ['gov', 'government', 'india', 'incometax', 'passport'],
            'Telecom Service (Generic)': ['mobile', 'telecom', 'broadband', 'recharge']
        }
        
        for generic_name, patterns in generic_patterns.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    return generic_name, 'Medium'
    
    return 'Unknown', 'Low'

def predict_with_ensemble():
    print("🔍 Starting ensemble phishing domain prediction...")
    
    # Load both models
    try:
        lexical_model = joblib.load("models/lexical_model.pkl")
        whois_model = joblib.load("models/whois_model.pkl")
        
        # Load label encoders
        lexical_encoder = joblib.load("models/lexical_label_encoder.pkl")
        whois_encoder = joblib.load("models/whois_label_encoder.pkl")
        
        # Load preprocessors
        lexical_scaler = joblib.load("models/lexical_scaler.pkl")
        lexical_selector = joblib.load("models/lexical_selector.pkl")
        whois_scaler = joblib.load("models/whois_scaler.pkl")
        
        # Load the specific feature names the lexical model expects
        lexical_features = joblib.load("models/lexical_features.pkl")
        lexical_full_features = joblib.load("models/lexical_full_features.pkl")
    except FileNotFoundError as e:
        print(f"❌ Model file not found: {e}")
        print("⚠️  Run training first: python -m src.models.train_lexical_model and python -m src.models.train_whois_model")
        return None
    
    # Load BOTH shortlisting datasets
    print("📁 Loading both shortlisting datasets...")
    
    # Part 1
    df_part1 = pd.read_excel("data/raw/PS-02_Shortlisting_set/Shortlisting_Data_Part_1.xlsx")
    df_part1 = df_part1.rename(columns={df_part1.columns[0]: 'domain'})
    df_part1['source_file'] = 'Part_1'
    print(f"✅ Part 1 loaded: {len(df_part1):,} domains")
    
    # Part 2  
    df_part2 = pd.read_excel("data/raw/PS-02_Shortlisting_set/Shortlisting_Data_Part_2.xlsx")
    df_part2 = df_part2.rename(columns={df_part2.columns[0]: 'domain'})
    df_part2['source_file'] = 'Part_2'
    print(f"✅ Part 2 loaded: {len(df_part2):,} domains")
    
    # Combine both datasets
    df_combined = pd.concat([df_part1, df_part2], ignore_index=True)
    total_domains = len(df_combined)
    print(f"📊 Combined total: {total_domains:,} domains")
    
    # ⚠️ CRITICAL FIX: Handle large datasets
    if total_domains > 10000:
        print("⚠️  Large dataset detected - optimizing for efficiency")
        print("⚠️  Using lexical-only prediction (skipping WHOIS for speed)")
        use_whois = False
    else:
        print("✅ Using full ensemble prediction (lexical + WHOIS)")
        use_whois = True
    
    # --- LEXICAL MODEL PREDICTION ---
    print("🔍 Extracting lexical features...")
    df_lexical = extract_url_features(df_combined, domain_col='domain')
    
    # Ensure all required features are present, add missing ones as 0
    for feature in lexical_full_features:
        if feature not in df_lexical.columns:
            df_lexical[feature] = 0
    
    # Select only the features the model was trained on, in the correct order
    X_lexical = df_lexical[lexical_full_features]
    
    print(f"📊 Lexical features shape: {X_lexical.shape}")
    print(f"📊 Expected features: {len(lexical_full_features)}")
    
    # Apply the same preprocessing steps used during training
    X_lexical_selected = lexical_selector.transform(X_lexical)
    X_lexical_scaled = lexical_scaler.transform(X_lexical_selected)
    
    # Get prediction probabilities from lexical model
    lex_proba = lexical_model.predict_proba(X_lexical_scaled)
    
    # --- WHOIS MODEL PREDICTION ---
    if use_whois:
        print("🔍 Extracting WHOIS features...")
        df_whois = extract_whois_features(df_combined, domain_col='domain')
        
        # Define the features the WHOIS model expects
        whois_cols = ['domain_age_days', 'is_new_domain', 'registrar_risk_score', 'has_privacy_protection']
        
        # Ensure WHOIS features exist
        for col in whois_cols:
            if col not in df_whois.columns:
                if col == 'domain_age_days':
                    df_whois[col] = -1
                elif col == 'is_new_domain':
                    df_whois[col] = 1
                elif col == 'registrar_risk_score':
                    df_whois[col] = 0.5
                elif col == 'has_privacy_protection':
                    df_whois[col] = 0
        
        X_whois = df_whois[whois_cols]
        X_whois_scaled = whois_scaler.transform(X_whois)
        
        # Get prediction probabilities from WHOIS model
        whois_proba = whois_model.predict_proba(X_whois_scaled)
        
        # --- ENSEMBLE PREDICTION ---
        print("✅ Using ensemble prediction (lexical + WHOIS)")
        avg_proba = (lex_proba + whois_proba) / 2
    else:
        # Use lexical-only for large datasets
        print("✅ Using lexical-only prediction (optimized for large dataset)")
        avg_proba = lex_proba
    
    # Final prediction
    ensemble_pred = (avg_proba[:, 1] > 0.5).astype(int)  # 1 = Phishing, 0 = Suspected
    
    # Decode numeric predictions back to labels
    labels = lexical_encoder.inverse_transform([0, 1])  # ['Suspected', 'Phishing']
    df_combined['predicted_label'] = [labels[pred] for pred in ensemble_pred]
    df_combined['confidence'] = np.max(avg_proba, axis=1)
    
    # 🎯 NEW: Identify CSE targets for phishing domains
    print("🎯 Identifying targeted CSEs for phishing domains...")
    cse_targets = []
    cse_confidences = []
    
    for domain in df_combined['domain']:
        target_cse, confidence = identify_cse_target(domain)
        cse_targets.append(target_cse)
        cse_confidences.append(confidence)
    
    df_combined['target_cse'] = cse_targets
    df_combined['cse_confidence'] = cse_confidences
    
    # Save results
    os.makedirs("outputs", exist_ok=True)
    
    # Save all predictions
    df_combined.to_csv("outputs/shortlisting_predictions.csv", index=False)
    print(f"✅ All predictions saved! → outputs/shortlisting_predictions.csv")
    
    # Save predictions by source file
    df_part1_pred = df_combined[df_combined['source_file'] == 'Part_1']
    df_part2_pred = df_combined[df_combined['source_file'] == 'Part_2']
    
    df_part1_pred.to_csv("outputs/shortlisting_predictions_part1.csv", index=False)
    df_part2_pred.to_csv("outputs/shortlisting_predictions_part2.csv", index=False)
    print(f"✅ Part 1 predictions saved: {len(df_part1_pred):,} domains")
    print(f"✅ Part 2 predictions saved: {len(df_part2_pred):,} domains")
    
    # Save high-confidence phishing (top 500 from combined)
    high_conf_phishing = df_combined[
        (df_combined['predicted_label'] == 'Phishing') & 
        (df_combined['confidence'] >= 0.90)
    ].nlargest(500, 'confidence')
    
    high_conf_phishing.to_csv("outputs/high_conf_phishing_top500.csv", index=False)
    print(f"📁 High-confidence phishing saved ({len(high_conf_phishing)} domains) → outputs/high_conf_phishing_top500.csv")
    
    # Enhanced CSE predictions with target mapping
    cse_phishing = df_combined[
        (df_combined['predicted_label'] == 'Phishing') & 
        (df_combined['target_cse'] != 'Unknown')
    ].nlargest(1000, 'confidence')
    
    cse_phishing.to_csv("outputs/enhanced_cse_predictions.csv", index=False)
    print(f"🎯 CSE-targeting phishing saved ({len(cse_phishing)} domains) → outputs/enhanced_cse_predictions.csv")
    
    # NEW: Save CSE-wise breakdown
    cse_breakdown = df_combined[df_combined['predicted_label'] == 'Phishing'].groupby('target_cse').size().reset_index(name='count')
    cse_breakdown = cse_breakdown.sort_values('count', ascending=False)
    cse_breakdown.to_csv("outputs/cse_target_breakdown.csv", index=False)
    print(f"📊 CSE target breakdown saved → outputs/cse_target_breakdown.csv")
    
    # Print summary statistics
    print(f"\n📊 PREDICTION SUMMARY:")
    print(f"   - Total domains processed: {total_domains:,}")
    print(f"   - Part 1 domains: {len(df_part1):,}")
    print(f"   - Part 2 domains: {len(df_part2):,}")
    print(f"   - Predicted Phishing: {len(df_combined[df_combined['predicted_label'] == 'Phishing']):,}")
    print(f"   - Predicted Suspected: {len(df_combined[df_combined['predicted_label'] == 'Suspected']):,}")
    print(f"   - High-confidence phishing (≥90%): {len(high_conf_phishing):,}")
    print(f"   - CSE-targeting phishing: {len(cse_phishing):,}")
    
    # Breakdown by CSE targets
    print(f"\n🎯 CSE TARGET BREAKDOWN (Top 10):")
    top_cses = cse_breakdown.head(10)
    for _, row in top_cses.iterrows():
        print(f"   - {row['target_cse']}: {row['count']:,} domains")
    
    # Breakdown by source file
    phishing_part1 = len(df_part1_pred[df_part1_pred['predicted_label'] == 'Phishing'])
    phishing_part2 = len(df_part2_pred[df_part2_pred['predicted_label'] == 'Phishing'])
    
    print(f"\n📊 BREAKDOWN BY DATASET:")
    print(f"   - Part 1 - Phishing: {phishing_part1:,}, Suspected: {len(df_part1_pred) - phishing_part1:,}")
    print(f"   - Part 2 - Phishing: {phishing_part2:,}, Suspected: {len(df_part2_pred) - phishing_part2:,}")
    
    if not use_whois:
        print(f"\n💡 Note: Used lexical-only prediction for efficiency with large dataset")
        print(f"💡 To use full ensemble, reduce dataset size below 10,000 domains")
    
    return df_combined

if __name__ == "__main__":
    predict_with_ensemble()