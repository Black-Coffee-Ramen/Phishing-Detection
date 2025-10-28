# src/features/visual_similarity.py
import os
import logging
from PIL import Image
import imagehash
from pdf2image import convert_from_path
from playwright.sync_api import sync_playwright

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ✅ Complete CSE references with multiple URLs per organization
CSE_REFERENCES = {
    "Airtel": ["https://airtel.in"],
    "Bank of Baroda": ["https://bankofbaroda.bank.in"],
    "Civil Registration System (MHA)": ["https://dc.crsorgi.gov.in"],
    "HDFC Group": ["https://hdfcbank.com", "https://hdfcergo.com", "https://hdfclife.com"],
    "IRCTC": ["https://www.irctc.co.in/"],
    "Indian Oil Corporation Limited (IOCL)": ["https://iocl.com"],
    "National Informatics Centre (NIC)": [
        "https://www.nic.gov.in",
        "https://email.gov.in",
        "https://kavach.mail.gov.in/mfid/secureLogin_showSecureLogin.action#!",
        "https://accounts.mgovcloud.in/signin?servicename=AaaServer&serviceurl=https%3A%2F%2Faccounts.mgovcloud.in%2Fhome"
    ],
    "Punjab National Bank (PNB)": ["https://pnb.bank.in"],
    "State Bank of India (SBI)": [
        "https://onlinesbi.sbi.bank.in",
        "https://sbi.bank.in/",
        "https://sbicard.com",
        "https://sbilife.co.in"
    ],
    "RGCCI (Registrar General & Census Commissioner of India)": ["https://dc.crsorgi.gov.in"]
}

REFERENCE_DIR = "reference/similarity_reference"
os.makedirs(REFERENCE_DIR, exist_ok=True)

def capture_cse_references(retries=2):
    """Capture reference screenshots of all official CSE sites with retry logic"""
    logger.info("📸 Starting capture of CSE reference screenshots...")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': 1366, 'height': 768},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        )
        
        for cse_name, urls in CSE_REFERENCES.items():
            for idx, url in enumerate(urls, 1):
                success = False
                for attempt in range(1, retries + 1):
                    try:
                        logger.info(f"🌐 Loading {url} ({cse_name}) [Attempt {attempt}/{retries}]")
                        
                        page = context.new_page()
                        page.goto(url, timeout=60000)  # 60 second timeout
                        page.wait_for_load_state("networkidle")
                        
                        # Generate safe filename
                        safe_name = f"{cse_name}_{idx}.png"
                        screenshot_path = os.path.join(REFERENCE_DIR, safe_name)
                        
                        # Capture full page screenshot
                        page.screenshot(path=screenshot_path, full_page=True)
                        page.close()
                        
                        logger.info(f"✅ Captured {cse_name} ({url}) → {safe_name}")
                        success = True
                        break
                        
                    except Exception as e:
                        logger.warning(f"⚠️ Attempt {attempt} failed for {cse_name} ({url}): {str(e)}")
                        if attempt < retries:
                            logger.info("🔄 Retrying...")
                        else:
                            logger.error(f"❌ Failed to capture {cse_name} ({url}) after {retries} retries")
                
        browser.close()
    
    logger.info("🎉 CSE reference screenshot capture completed!")

def convert_pdf_to_png(pdf_path, png_path):
    """Convert first page of PDF to PNG for visual comparison"""
    try:
        images = convert_from_path(pdf_path, first_page=1, last_page=1, dpi=150)
        images[0].save(png_path, 'PNG', quality=85)
        logger.debug(f"✅ Converted {pdf_path} → {png_path}")
        return True
    except Exception as e:
        logger.warning(f"⚠️ PDF conversion failed for {pdf_path}: {str(e)}")
        return False

def get_phash(image_path):
    """Get perceptual hash of an image for similarity comparison"""
    try:
        with Image.open(image_path) as img:
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            return imagehash.phash(img)
    except Exception as e:
        logger.warning(f"⚠️ Failed to hash {image_path}: {str(e)}")
        return None

def is_visually_similar(image_path1, image_path2, threshold=15):
    """
    Check if two images are visually similar using perceptual hashing
    Lower threshold = stricter matching (10-20 recommended)
    """
    hash1 = get_phash(image_path1)
    hash2 = get_phash(image_path2)
    
    if hash1 is None or hash2 is None:
        return False
        
    distance = hash1 - hash2
    similarity_percent = max(0, 100 - (distance * 100 / 64))  # 64 is max hash distance
    
    logger.debug(f"🖼️ Visual similarity: {distance} distance ({similarity_percent:.1f}% similar)")
    return distance < threshold

def validate_cse_phishing(domain, evidence_pdf_path, threshold=15):
    """
    Validate if a phishing domain visually mimics any CSE
    Returns: (is_phishing, matched_cse, similarity_info) or (False, None, None)
    """
    if not os.path.exists(evidence_pdf_path):
        logger.warning(f"⚠️ Evidence PDF not found: {evidence_pdf_path}")
        return False, None, None
        
    # Convert PDF to PNG for comparison
    png_path = evidence_pdf_path.replace(".pdf", ".png")
    if not convert_pdf_to_png(evidence_pdf_path, png_path):
        return False, None, None
    
    if not os.path.exists(png_path):
        logger.warning(f"⚠️ Converted PNG not found: {png_path}")
        return False, None, None
    
    best_match = None
    best_similarity = 0
    
    # Check against all CSE references
    for cse_name, urls in CSE_REFERENCES.items():
        for idx, url in enumerate(urls, 1):
            ref_path = os.path.join(REFERENCE_DIR, f"{cse_name}_{idx}.png")
            
            if not os.path.exists(ref_path):
                logger.debug(f"⚠️ Reference not found: {ref_path}")
                continue
            
            hash1 = get_phash(png_path)
            hash2 = get_phash(ref_path)
            
            if hash1 is not None and hash2 is not None:
                distance = hash1 - hash2
                similarity = max(0, 100 - (distance * 100 / 64))
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = (cse_name, url, distance, similarity)
                
                if distance < threshold:
                    logger.info(f"🎯 {domain} visually matches {cse_name}! "
                               f"(Distance: {distance}, Similarity: {similarity:.1f}%)")
                    return True, cse_name, {"distance": distance, "similarity": similarity}
    
    # Log best match even if below threshold
    if best_match:
        cse_name, url, distance, similarity = best_match
        logger.info(f"📊 Best match for {domain}: {cse_name} "
                   f"(Distance: {distance}, Similarity: {similarity:.1f}%)")
    
    return False, None, None

def get_all_reference_files():
    """Get list of all available reference screenshot files"""
    reference_files = {}
    for cse_name, urls in CSE_REFERENCES.items():
        reference_files[cse_name] = []
        for idx, url in enumerate(urls, 1):
            ref_path = os.path.join(REFERENCE_DIR, f"{cse_name}_{idx}.png")
            if os.path.exists(ref_path):
                reference_files[cse_name].append({
                    'url': url,
                    'path': ref_path,
                    'exists': True
                })
            else:
                reference_files[cse_name].append({
                    'url': url,
                    'path': ref_path,
                    'exists': False
                })
    return reference_files

# Example usage
if __name__ == "__main__":
    # Capture reference screenshots (run once)
    capture_cse_references()
    
    # Example of how to use in your pipeline:
    # is_phishing, matched_cse, similarity_info = validate_cse_phishing(
    #     domain="fake-sbi-phishing.com",
    #     evidence_pdf_path="evidences/fake-sbi-phishing.com.pdf",
    #     threshold=15
    # )