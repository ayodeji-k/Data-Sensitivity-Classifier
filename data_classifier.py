import re

# Define sensitivity levels
SENSITIVITY_LEVELS = {
    "Public": [],
    "Internal": ["internal", "confidential"],
    "Confidential": ["ssn", "credit card", "password", "proprietary"],
    "Restricted": ["classified", "top secret", "government only"]
}

REGEX_PATTERNS = {
    "SSN": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    "Phone": r"\b(?:\+\d{1,3}[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b",
    "IP Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
}

def classify_text(text):
    """
    Classify text based on sensitivity keywords and regex patterns.
    Returns tuple of (classification_level, matches_found)
    """
    classification = "Public"
    matches_found = []
    
    # Check for keyword-based classification
    for level, keywords in SENSITIVITY_LEVELS.items():
        for keyword in keywords:
            if keyword.lower() in text.lower():
                classification = max(classification, level, key=lambda x: list(SENSITIVITY_LEVELS.keys()).index(x))
                matches_found.append(f"Keyword: {keyword}")
    
    # Check for regex-based classification
    for label, pattern in REGEX_PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            classification = "Restricted"  # Highest sensitivity for regex matches
            # Mask the sensitive data in the output
            masked_value = '*' * len(match.group())
            matches_found.append(f"{label}: {masked_value}")
    
    return classification, matches_found

# Update main execution
if __name__ == "__main__":
    print("Data Sensitivity Classifier - Legal Use Only")
    print("WARNING: Use only with authorized data\n")
    
    try:
        sample_text = input("Enter text to classify: ")
        classification, matches = classify_text(sample_text)
        print(f"\nSensitivity Classification: {classification}")
        
        if matches:
            print("\nSensitive content found:")
            for match in matches:
                print(f"- {match}")
        
    except KeyboardInterrupt:
        print("\nClassification cancelled by user")
    except Exception as e:
        print(f"\nError during classification: {str(e)}") 