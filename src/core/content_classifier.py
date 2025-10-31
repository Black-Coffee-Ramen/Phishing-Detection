# src/core/content_classifier.py
import re
from bs4 import BeautifulSoup

class ContentClassifier:
    def __init__(self):
        self.parked_indicators = [
            'domain for sale', 'this domain is parked', 'buy this domain',
            'sedoparking', 'parking crew', 'domain parking',
            'お名前.com', 'onamae.com'  # Common parking pages
        ]
        
        self.credential_indicators = [
            'type="password"', 'login', 'sign in', 'log in',
            'username', 'email', 'password', 'credentials'
        ]
    
    def classify_content_state(self, html, visual_analysis):
        """Classify page content according to rules"""
        
        html_lower = html.lower()
        
        # Check for parked pages
        if any(indicator in html_lower for indicator in self.parked_indicators):
            return 'parked'
        
        # Check for credential collection
        has_credentials = self.detect_credential_forms(html)
        
        # Check visual similarity
        is_visual_lookalike = visual_analysis.get('is_lookalike', False)
        
        if is_visual_lookalike and has_credentials:
            return 'lookalike'
        elif not has_credentials and not is_visual_lookalike:
            return 'unrelated'
        elif has_credentials and not is_visual_lookalike:
            return 'suspicious_form'  # Could be legitimate but monitor
        
        return 'unclassified'
    
    def detect_credential_forms(self, html):
        """Detect password fields and login forms"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check for password inputs
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                return True
            
            # Check for common login form patterns
            login_indicators = ['login', 'signin', 'log-in', 'sign-in']
            for indicator in login_indicators:
                # Find forms with login-related text
                form_elements = soup.find_all(['form', 'input', 'button'])
                for element in form_elements:
                    if element.get('name', '').lower().find(indicator) != -1:
                        return True
                    if element.get('id', '').lower().find(indicator) != -1:
                        return True
                    if element.get('class') and any(indicator in cls.lower() for cls in element.get('class')):
                        return True
            
            return False
        except Exception as e:
            print(f"Error detecting credential forms: {e}")
            return False
    
    def detect_parked_page(self, html):
        """Enhanced parked page detection"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            text_content = soup.get_text().lower()
            
            # Check for parked page indicators
            parked_keywords = ['parked', 'for sale', 'this domain', 'buy now']
            parked_count = sum(1 for keyword in parked_keywords if keyword in text_content)
            
            # Check for ad-heavy pages (common in parking)
            ads_count = len(soup.find_all(['iframe', 'script']))
            text_ratio = len(text_content.strip()) / max(1, len(html))
            
            # Heuristic: parked pages have low text ratio and high ad/script count
            if parked_count >= 2 or (text_ratio < 0.1 and ads_count > 5):
                return True
                
            return False
        except Exception as e:
            print(f"Error detecting parked page: {e}")
            return False