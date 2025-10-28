import os
import logging
from src.features.visual_similarity import validate_cse_phishing

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Complete CSE domain mappings for final reporting
CSE_DOMAIN_MAPPINGS = {
    "Airtel": "airtel.in",
    "Bank_of_Baroda": "bankofbaroda.in", 
    "RGCCI": "dc.crsorgi.gov.in",
    "HDFC_Group": "hdfcbank.com",
    "IRCTC": "irctc.co.in",
    "Indian_Oil": "iocl.com",
    "NIC": "nic.gov.in",
    "PNB": "pnbindia.in",
    "SBI": "onlinesbi.sbi",
    "ICICI": "icicibank.com"  # ✅ Added as requested
}

def classify_lexical_only(domain):
    """
    Fallback classification using only lexical analysis
    when visual evidence is unavailable
    """
    logger.info(f"🔤 Fallback to lexical analysis for {domain}")
    
    # Your existing lexical analysis logic here
    # This should return the same structure as classify_domain
    
    # Example simple lexical check
    suspicious_keywords = ['login', 'secure', 'verify', 'account', 'banking', 'online']
    domain_lower = domain.lower()
    
    keyword_matches = [kw for kw in suspicious_keywords if kw in domain_lower]
    
    if keyword_matches:
        return {
            "domain": domain,
            "label": "Suspected",
            "phishing_type": "Lexical Analysis",
            "matched_cse": None,
            "cse_domain": None,
            "similarity_score": 0,
            "hash_distance": None,
            "confidence": "Low",
            "detection_method": "lexical_fallback",
            "matched_keywords": keyword_matches
        }
    else:
        return {
            "domain": domain,
            "label": "Benign",  # Or whatever your baseline is
            "phishing_type": None,
            "matched_cse": None,
            "cse_domain": None,
            "similarity_score": 0,
            "hash_distance": None,
            "confidence": "Very Low",
            "detection_method": "lexical_fallback",
            "matched_keywords": []
        }

def classify_domain(domain, evidence_pdf_path, threshold=15):
    """
    Main classification function that uses visual similarity
    to detect phishing domains mimicking CSE websites
    """
    logger.info(f"🔍 Analyzing {domain} for visual phishing...")
    
    # ✅ Check for failed evidence capture
    if not os.path.exists(evidence_pdf_path) or "screenshot_failed" in evidence_pdf_path:
        logger.warning(f"⚠️ Evidence missing/failed for {domain}, using lexical fallback")
        return classify_lexical_only(domain)
    
    try:
        # Use visual similarity detection
        is_phishing, matched_cse, similarity_info = validate_cse_phishing(
            domain=domain,
            evidence_pdf_path=evidence_pdf_path,
            threshold=threshold
        )
        
        # Determine final label and details
        if is_phishing:
            label = "Phishing"
            cse_domain = CSE_DOMAIN_MAPPINGS.get(matched_cse, "unknown-cse")
            logger.info(f"🚨 PHISHING: {domain} visually mimics {matched_cse} ({cse_domain})")
            
            return {
                "domain": domain,
                "label": label,
                "phishing_type": "Visual Mimicry",
                "matched_cse": matched_cse,
                "cse_domain": cse_domain,
                "similarity_score": similarity_info.get('similarity', 0),
                "hash_distance": similarity_info.get('distance', 0),
                "confidence": "High",
                "detection_method": "visual_similarity",
                "evidence_path": evidence_pdf_path
            }
        else:
            label = "Suspected"
            logger.info(f"⚠️ SUSPECTED: {domain} - No strong visual match found")
            
            return {
                "domain": domain,
                "label": label,
                "phishing_type": "Generic Suspicious",
                "matched_cse": None,
                "cse_domain": None,
                "similarity_score": similarity_info.get('similarity', 0) if similarity_info else 0,
                "hash_distance": similarity_info.get('distance', 0) if similarity_info else None,
                "confidence": "Medium",
                "detection_method": "visual_similarity",
                "evidence_path": evidence_pdf_path
            }
            
    except Exception as e:
        logger.error(f"❌ Visual analysis failed for {domain}: {e}")
        # Fallback to lexical analysis
        return classify_lexical_only(domain)

def process_domains_batch(domain_list):
    """Process multiple domains through the visual similarity pipeline"""
    results = []
    
    for domain in domain_list:
        # Assuming you have a function that captures PDF evidence
        evidence_pdf_path = f"evidences_temp/{domain}.pdf"
        
        # Check if evidence capture failed (you might have a different indicator)
        failed_evidence_path = f"evidences_temp/{domain}_screenshot_failed.pdf"
        if os.path.exists(failed_evidence_path):
            evidence_pdf_path = failed_evidence_path
        
        result = classify_domain(domain, evidence_pdf_path)
        results.append(result)
    
    return results

def print_detection_summary(results):
    """Print a nice summary of detection results"""
    phishing_count = sum(1 for r in results if r['label'] == 'Phishing')
    suspected_count = sum(1 for r in results if r['label'] == 'Suspected')
    benign_count = sum(1 for r in results if r['label'] == 'Benign')
    
    print("\n" + "="*50)
    print("🎯 DETECTION SUMMARY")
    print("="*50)
    print(f"🔴 Phishing: {phishing_count}")
    print(f"🟡 Suspected: {suspected_count}")
    print(f"🟢 Benign: {benign_count}")
    print(f"📊 Total: {len(results)}")
    print("="*50)
    
    # Show phishing matches
    phishing_domains = [r for r in results if r['label'] == 'Phishing']
    if phishing_domains:
        print("\n🚨 PHISHING DOMAINS DETECTED:")
        for result in phishing_domains:
            print(f"  • {result['domain']} → Mimics {result['matched_cse']} "
                  f"({result['similarity_score']:.1f}% similar)")

# Run the classification
if __name__ == "__main__":
    # Example domains to test
    test_domains = [
        "nichequalifyforcapital.com",
        "sbi-secure-login.com", 
        "hdfc-online-banking.com",
        "icici-verification.com",  # Will use ICICI mapping
        "failed-capture-domain.com"  # Will trigger lexical fallback
    ]
    
    results = process_domains_batch(test_domains)
    
    # Print detailed results
    for result in results:
        print(f"\nDomain: {result['domain']}")
        print(f"Label: {result['label']}")
        print(f"Detection Method: {result['detection_method']}")
        print(f"Confidence: {result['confidence']}")
        if result['matched_cse']:
            print(f"Mimics: {result['matched_cse']} ({result['cse_domain']})")
            print(f"Similarity: {result['similarity_score']:.1f}%")
        if result.get('matched_keywords'):
            print(f"Keywords: {', '.join(result['matched_keywords'])}")
    
    # Print summary
    print_detection_summary(results)