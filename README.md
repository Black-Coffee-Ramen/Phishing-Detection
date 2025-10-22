# AI-Powered Phishing Domain Detection System

## Project Overview

This project implements an AI-based monitoring and detection system for identifying phishing domains and URLs targeting Critical Sector Entities (CSEs). The solution uses machine learning to automatically detect and classify suspicious domains in near real-time, helping prevent data breaches and financial losses.

**Main Objectives:**
- Detect phishing domains targeting Critical Sector Entities (CSEs)
- Monitor suspected domains over extended periods (3+ months)
- Provide real-time alerts and comprehensive reporting
- Scale to process millions of domains efficiently

## Problem Statement

Phishing attacks remain one of the most persistent cybersecurity threats, with attackers registering domains that closely resemble legitimate Critical Sector Entities (CSEs) to deceive users into revealing sensitive information. Traditional detection methods are insufficient against evolving tactics like:
- Typosquatting/lookalike domains
- Parked domains with no content
- Use of tunneling services (Ngrok, Vercel)
- Internationalized Domain Name (IDN) homograph attacks

**Real-world Significance:** This solution addresses urgent needs in banking, government, and critical infrastructure sectors where phishing attacks can lead to massive data breaches, financial losses, and national security threats.

## Data Sources

### Training Dataset (`PS02_Training_set/`)
- **Source:** NCIIPC AI Grand Challenge
- **Size:** 1,043 labeled domains
- **Structure:**
  - 351 confirmed phishing domains
  - 692 suspected domains
  - 10 Critical Sector Entities (CSEs)
- **Features:** Domain names, CSE targets, evidence screenshots

### Mock Dataset (`Mock data along with Ground Truth/`)
- **Purpose:** Validation and self-evaluation
- **Size:** 15 Excel files with 1,000+ samples each
- **Timeline:** July-September 2025 updates
- **Content:** Ground truth labels for model validation

### Pre-Evaluation Dataset (`PS_02_Shortlisting_set/`)
- **Purpose:** Stage 1 competition evaluation
- **Size:** 1,088,266 domains total
  - Part 1: 572,824 domains
  - Part 2: 515,442 domains
- **Format:** Mixed legitimate and phishing domains for classification

## 📁 Folder Structure

```
C:.
│   b4d57cca-0b63-4998-804b-1a0a46bf578c.pdf          # Problem statement
│   PS-02_Phishing_Detection_CSE_Domains_Dataset_for_Stage_1.xlsx
│   requirements.txt                                   # Python dependencies
│
├───src/                                              # Source code
│   │   actual_training_pipeline.py                   # Main training script
│   │   fast_pre_evaluation_detector.py              # Optimized detection
│   │   quick_start.py                               # Initial setup
│   │   analyze_features.py                          # Model analysis
│   │
│   ├───data_processing/
│   │       dataset_analyzer.py
│   │       dataset_loader.py
│   │
│   ├───feature_engineering/
│   │       advanced_feature_extractor.py
│   │       simple_feature_extractor.py
│   │
│   ├───ml_models/
│   │       model_trainer.py
│   │       ensemble_model.py
│   │
│   └───monitoring/
│           domain_monitor.py
│
├───Mock data along with Ground Truth for NCIIPC AI Grand Challenge - PS02/
│       Mock_Data_01_08_2025.xlsx
│       Mock_Data_03_09_2025.xlsx
│       ... (15 total mock datasets)
│
├───PS02_Training_set/
│   └───PS02_Training_set
│       └───PS02_Training_set
│           │   PS02_Training_set.xlsx               # Main training data
│           │
│           └───Evidences/                           # 89 phishing page screenshots
│                   aeludi.cyou.pdf
│                   airtel-merchants.in.pdf
│                   ... (phishing evidence PDFs)
│
├───PS_02_Shortlisting_set (Pre-Evaluation)/
│   └───PS-02_Shortlisting_set
│           Shortlisting_Data_Part_1.xlsx           # 572K domains
│           Shortlisting_Data_Part_2.xlsx           # 515K domains
│
├───models/                                          # Trained ML models
│       phishing_detector_v1.pkl
│       model_info.pkl
│
└───outputs/                                         # Results and analysis
        feature_summary.csv
        confusion_matrix.png
        feature_importance.png
        PS-02_AIGR-123456_Submission_Set.xlsx
```

##  Approach & Methodology

### Data Preprocessing
- Automated dataset loading and validation
- Handling of missing values and data type conversion
- Domain parsing and normalization using `tldextract`

### Feature Engineering
**URL & Domain Features (24 total features):**
- Structural: URL length, domain length, number of dots/hyphens/special characters
- Entropy: Shannon entropy calculations for URL and domain
- Subdomain analysis: Count, complexity, character patterns
- TLD classification: Common, country-specific, and new TLDs
- CSE targeting: Keyword matching and lookalike detection
- Typosquatting: Levenshtein distance to known CSE domains

### Model Training
- **Algorithm:** Random Forest Classifier with balanced class weights
- **Ensemble Method:** Voting classifier with multiple base estimators
- **Cross-validation:** 5-fold stratified cross-validation
- **Hyperparameters:**
  - `n_estimators=100`
  - `max_depth=20` 
  - `class_weight='balanced'`
  - `random_state=42`

### Detection Pipeline
1. **Data Collection** → Multi-source domain crawling
2. **Feature Extraction** → Real-time feature computation
3. **ML Classification** → Ensemble model prediction
4. **Alert Generation** → Confidence-based scoring
5. **Monitoring** → Continuous domain tracking

## Evaluation Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| **Accuracy** | 90.43% | Overall classification correctness |
| **Precision** | 87% | Correct phishing predictions among all phishing alerts |
| **Recall** | 84% | Percentage of actual phishing domains detected |
| **F1-Score** | 86% | Harmonic mean of precision and recall |
| **ROC-AUC** | 0.94 | Model discrimination capability |

**Competition Evaluation Weights:**
- True Positives (Phishing Detection): 75%
- False Positives: 25%
- Approach Methodology: 20%
- Team Capability: 10%

##  Results Summary

### Model Performance
- **Training Accuracy:** 90.43% on 1,043 domains
- **Detection Rate:** 7.28% (364 phishing domains from 5,000 sample)
- **Processing Speed:** ~1,000 domains/minute
- **Feature Count:** 24 optimized numerical features

### Key Feature Importance
| Feature | Importance | Correlation with Phishing |
|---------|------------|---------------------------|
| `contains_cse_keyword` | 14.77% | 0.687 |
| `num_subdomains` | 13.97% | 0.297 |
| `domain_entropy` | 12.14% | 0.279 |
| `url_entropy` | 10.06% | 0.380 |
| `levenshtein_distance` | 7.87% | 0.224 |

### Visual Summaries
- **Confusion Matrix:** `outputs/confusion_matrix.png`
- **Feature Importance:** `outputs/feature_importance.png`
- **Feature Distributions:** `outputs/feature_distributions.png`

##  Dependencies & Requirements

### Core Python Libraries
```python
pandas>=1.5.0          # Data manipulation
numpy>=1.21.0          # Numerical computing
scikit-learn>=1.0.0    # Machine learning
xgboost>=1.5.0         # Ensemble learning
tldextract>=3.1.0      # Domain parsing
python-whois>=0.8.0    # WHOIS information
requests>=2.25.0       # HTTP requests
beautifulsoup4>=4.9.0  # HTML parsing
openpyxl>=3.0.0        # Excel file handling
joblib>=1.0.0          # Model serialization
```

### Installation
```bash
# Install all dependencies
pip install -r requirements.txt

# Or install individually
pip install pandas scikit-learn xgboost tldextract python-whois requests beautifulsoup4 openpyxl joblib
```

##  How to Run

### Step 1: Initial Setup
```bash
# Clone or download the project files
# Ensure all dataset folders are in the root directory

# Run initial analysis
python src/quick_start.py
```

### Step 2: Model Training
```bash
# Train the phishing detection model
python src/actual_training_pipeline.py

# This will create:
# - models/phishing_detector_v1.pkl
# - outputs/feature_summary.csv
# - Performance visualizations
```

### Step 3: Run Detection
```bash
# Detect phishing domains on sample data
python src/fast_pre_evaluation_detector.py

# For full-scale processing (1M+ domains)
python src/full_scale_processor.py
```

### Step 4: Generate Submission
```bash
# Create competition submission package
python src/create_submission_package.py
```

### Step 5: Analysis & Monitoring
```bash
# Analyze model performance and features
python src/analyze_features.py

# Start continuous monitoring
python src/monitoring/domain_monitor.py
```

##  Future Work

### Immediate Improvements
- [ ] **Real-time Dashboard:** Web interface for monitoring and alerts
- [ ] **Enhanced Features:** SSL certificate analysis, image similarity
- [ ] **Deep Learning:** CNN-based visual similarity detection
- [ ] **API Integration:** RESTful API for domain checking

### Advanced Features
- [ ] **Behavioral Analysis:** User interaction patterns
- [ ] **Temporal Analysis:** Domain lifecycle monitoring
- [ ] **Network Analysis:** IP reputation and hosting patterns
- [ ] **Multi-language Support:** International phishing detection

### Scalability
- [ ] **Distributed Processing:** Apache Spark for massive datasets
- [ ] **Cloud Deployment:** AWS/Azure scalable architecture
- [ ] **Stream Processing:** Kafka for real-time domain feeds

##  Contributors & Acknowledgments

### Team
- **Developer:** Athiyo Chakma
- **Institution:** Indraprastha Institute of Information Technology Delhi
- **Competition:** NCIIPC AI Grand Challenge 2025

### Acknowledgments
- **Data Source:** National Critical Information Infrastructure Protection Centre (NCIIPC)
- **Competition:** Startup India AI Grand Challenge - Problem Statement 02
- **Mentors:** Competition mentors and cybersecurity experts

### References
- NCIIPC AI Grand Challenge Problem Statement
- Cybersecurity threat intelligence frameworks
- Machine learning for cybersecurity research papers

## 📄 License

```markdown
MIT License

Copyright (c) 2025 Phishing Detection Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

##  Support & Contact

For questions, issues, or contributions:
- **Email:** athiyo22118@iiitd.ac.in
- **GitHub Issues:** https://github.com/Black-Coffee-Ramen/Phishing-Detection/issues
- **Documentation:** [Link to detailed documentation]

---

**⭐ If this project helped you, please consider giving it a star on GitHub!**
