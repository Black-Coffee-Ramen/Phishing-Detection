# src/utils/cse_mapper.py
import pandas as pd
import os
import re

def load_cse_reference():
    """
    Load official CSE domains dataset.
    Returns a dict: {domain: organisation_name}
    """
    ref_path = "data/processed/PS-02  Phishing Detection CSE_Domains_Dataset_for_Stage_1.xlsx"
    df = pd.read_excel(ref_path)

    # Forward-fill missing organisation names
    df['Organisation Name'] = df['Organisation Name'].ffill()
    df = df.dropna(subset=['Whitelisted Domains'])
    
    # Normalize domains
    df['Whitelisted Domains'] = df['Whitelisted Domains'].astype(str).str.strip().str.lower()
    cse_domain_to_name = dict(zip(df['Whitelisted Domains'], df['Organisation Name']))
    return cse_domain_to_name

def normalize_domain(domain):
    """
    Lowercase, remove 'www.', strip whitespace.
    """
    domain = domain.lower().strip()
    domain = re.sub(r'^www\.', '', domain)
    return domain

def map_phishing_domain_to_cse(phishing_domain, cse_domain_to_name=None):
    """
    Map a phishing domain to its CSE only if it contains official keywords.
    Returns (CSE Name, official domain)
    """
    domain = normalize_domain(phishing_domain)
    
    # Only map if domain contains CSE keywords
    if 'crsorgi' in domain or 'dc.crs' in domain:
        return "Registrar General and Census Commissioner of India (RGCCI)", "dc.crsorgi.gov.in"
    if 'irctc' in domain:
        return "Indian Railway Catering and Tourism Corporation (IRCTC)", "irctc.co.in"
    if 'nic' in domain or domain.endswith('.gov.in'):
        return "National Informatics Centre (NIC)", "nic.gov.in"
    if 'sbi' in domain or 'onlinesbi' in domain:
        return "State Bank of India (SBI)", "onlinesbi.sbi"
    if 'icici' in domain:
        return "ICICI Bank", "icicibank.com"
    if 'hdfc' in domain:
        return "HDFC Bank", "hdfcbank.com"
    if 'pnb' in domain:
        return "Punjab National Bank (PNB)", "pnbindia.in"
    if 'bob' in domain or 'bankofbaroda' in domain:
        return "Bank of Baroda (BoB)", "bankofbaroda.in"
    if 'airtel' in domain:
        return "Airtel", "airtel.in"
    
    return "Unknown CSE", "unknown"


# Example usage
if __name__ == "__main__":
    cse_domains = load_cse_reference()
    test_domains = [
        "onlinesbi.sbi", "dc.crsorgi.gov.in", "hdfclife.com", "unknownsite.com"
    ]
    for d in test_domains:
        cse_name, official = map_phishing_domain_to_cse(d, cse_domains)
        print(f"{d} → {cse_name} ({official})")