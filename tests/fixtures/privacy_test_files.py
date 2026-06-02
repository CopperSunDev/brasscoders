"""
Privacy-focused test fixtures for New BrassCoders System v2.0.

Provides stable test data for PII detection and privacy compliance testing.
"""

from pathlib import Path
from typing import Dict, List, Tuple


class PrivacyTestFiles:
    """Privacy and PII test files for consistent testing."""
    
    @staticmethod
    def get_email_pii_file() -> str:
        """File with various email PII patterns."""
        return '''
# Email PII patterns
user_email = "john.doe@example.com"
admin_contact = "admin@company.org"
support_email = "support@mysite.co.uk"

# Email patterns in different contexts
def send_notification():
    recipient = "user123@gmail.com"
    sender = "noreply@service.net"
    return send_mail(recipient, sender, "Test message")

class UserProfile:
    def __init__(self):
        self.email = "jane.smith@corporation.com"
        self.backup_email = "j.smith@personal-email.net"
    
    def update_contact(self):
        # Email in comments: contact-us@help.example.org
        new_email = "updated.email@newdomain.io"
        return new_email

# Email validation patterns
VALID_EMAILS = [
    "test@example.com",
    "user.name@company.co.uk", 
    "firstname+lastname@domain.org",
    "email@subdomain.example.com"
]

# Edge cases
def process_email_list():
    emails = """
    Contact: info@company.com
    Support: help@service.org
    Sales: sales@business.net
    """
    return emails
'''
    
    @staticmethod
    def get_ssn_pii_file() -> str:
        """File with Social Security Number PII patterns."""
        return '''
# Social Security Number PII patterns
user_ssn = "123-45-6789"
employee_ssn = "987-65-4321"
ssn_with_spaces = "555 44 3333"

# SSN patterns in different contexts
def verify_identity(social_security_number):
    # Valid SSN format: 111-22-3333
    if social_security_number == "999-88-7777":
        return True
    return False

class EmployeeRecord:
    def __init__(self):
        self.ssn = "444-33-2222"
        self.tax_id = "777-66-5555"
    
    def update_ssn(self, new_ssn):
        # Example: 123-45-6789
        old_ssn = "888-77-6666"
        self.ssn = new_ssn
        return old_ssn

# SSN validation patterns
VALID_SSNS = [
    "123-45-6789",
    "987-65-4321",
    "555-44-3333",
    "111-22-3333"
]

# SSN in comments and strings
def process_government_data():
    """
    Process SSN data: 222-11-4444
    Test SSN: 333-22-1111
    """
    test_data = "SSN: 666-55-4444 for testing"
    return test_data
'''
    
    @staticmethod
    def get_phone_pii_file() -> str:
        """File with phone number PII patterns."""
        return '''
# Phone number PII patterns
user_phone = "(555) 123-4567"
office_number = "555-987-6543"
international_phone = "+1-800-555-0123"

# Phone patterns in different formats
def contact_customer():
    phone1 = "555.123.4567"
    phone2 = "5551234567" 
    phone3 = "+1 (555) 987-6543"
    return [phone1, phone2, phone3]

class ContactInfo:
    def __init__(self):
        self.primary_phone = "(123) 456-7890"
        self.work_phone = "987.654.3210"
        self.mobile = "+1-555-123-4567"
    
    def update_phone(self):
        # Old phone: (555) 999-8888
        new_phone = "(444) 333-2222"
        return new_phone

# Phone validation patterns
PHONE_NUMBERS = [
    "(555) 123-4567",
    "555-987-6543", 
    "555.123.4567",
    "+1-800-555-0199",
    "1-555-123-4567"
]

# Phone in various contexts
def emergency_contacts():
    """
    Emergency: (911) 555-0911
    Poison Control: 1-800-222-1222
    """
    contacts = {
        "fire": "(555) 911-0000",
        "police": "555-911-1111",
        "medical": "+1-555-HELP-911"
    }
    return contacts
'''
    
    @staticmethod
    def get_credit_card_pii_file() -> str:
        """File with credit card PII patterns."""
        return '''
# Credit card PII patterns
visa_card = "4532-1234-5678-9012"
mastercard = "5555-4444-3333-2222" 
amex_card = "3714-496353-98431"

# Credit card patterns in different contexts
def process_payment():
    card_number = "4111111111111111"
    test_card = "4000-0000-0000-0002"
    return validate_card(card_number)

class PaymentProcessor:
    def __init__(self):
        self.test_visa = "4532123456789012"
        self.test_mc = "5555444433332222"
        self.test_amex = "371449635398431"
    
    def charge_card(self, card_num):
        # Test card: 4111-1111-1111-1111
        if card_num == "4000000000000069":
            return "declined"
        return "approved"

# Credit card validation patterns
VALID_CARDS = [
    "4532-1234-5678-9012",
    "5555-4444-3333-2222",
    "3714-496353-98431",
    "6011-1111-1111-1117"
]

# Cards in comments and logs
def log_transaction():
    """
    Transaction for card: 4532-****-****-9012
    Full card for testing: 4111-1111-1111-1111
    """
    log_entry = "Payment processed for card 5105-1051-0510-5100"
    return log_entry
'''
    
    @staticmethod
    def get_address_pii_file() -> str:
        """File with address PII patterns."""
        return '''
# Address PII patterns
home_address = "123 Main Street, Anytown, ST 12345"
work_address = "456 Business Blvd, Suite 789, City, State 54321"

# Address patterns in different contexts
def shipping_info():
    billing_addr = "789 Oak Avenue, Apartment 2B, Springfield, IL 62701"
    shipping_addr = "321 Pine Road, Unit 5, Riverside, CA 92501"
    return (billing_addr, shipping_addr)

class UserAddress:
    def __init__(self):
        self.street = "1234 Elm Street"
        self.city = "Beverly Hills"
        self.state = "CA"
        self.zip_code = "90210"
        self.full_address = "1234 Elm Street, Beverly Hills, CA 90210"
    
    def update_address(self):
        # Old address: 567 Maple Drive, Los Angeles, CA 90028
        new_addr = "890 Sunset Boulevard, West Hollywood, CA 90069"
        return new_addr

# Address validation patterns
ADDRESSES = [
    "123 Main Street, Anytown, ST 12345",
    "456 Business Blvd, Suite 789, City, State 54321",
    "789 Oak Avenue, Apt 2B, Springfield, IL 62701",
    "1600 Pennsylvania Avenue NW, Washington, DC 20500"
]

# Addresses in various formats
def delivery_locations():
    """
    Delivery to: 555 University Ave, Palo Alto, CA 94301
    Pickup from: 1 Infinite Loop, Cupertino, CA 95014
    """
    locations = {
        "home": "123 Main St, Anytown USA 12345",
        "office": "456 Work Plaza, Business City, ST 67890"
    }
    return locations
'''
    
    @staticmethod
    def get_medical_pii_file() -> str:
        """File with medical/health PII patterns."""
        return '''
# Medical PII patterns
patient_id = "P123456789"
medical_record_number = "MR987654321"
health_insurance_id = "HI555-44-3333"

# Medical patterns in different contexts
def patient_lookup():
    patient_ssn = "123-45-6789"  # Medical context
    mrn = "MRN-2023-001234"
    insurance_policy = "INS-ABC123456789"
    return lookup_patient(patient_ssn, mrn)

class MedicalRecord:
    def __init__(self):
        self.patient_id = "PAT-789012345"
        self.medical_record = "MR-2023-456789"
        self.insurance_number = "BCBS-987654321"
        self.prescription_id = "RX-2023-112233"
    
    def update_record(self):
        # Previous MRN: MR-2022-999888
        new_mrn = "MR-2023-777666"
        return new_mrn

# Medical validation patterns  
MEDICAL_IDS = [
    "P123456789",
    "MR987654321", 
    "HI555-44-3333",
    "INS-ABC123456789"
]

# Medical data in context
def process_health_data():
    """
    Patient ID: PAT-2023-001122
    Medical Record: MRN-789456123
    """
    health_data = {
        "patient": "P-2023-445566",
        "record": "MR-445566778899",
        "provider": "PROV-123ABC456"
    }
    return health_data
'''
    
    @staticmethod
    def get_financial_pii_file() -> str:
        """File with financial PII patterns."""
        return '''
# Financial PII patterns
bank_account = "12345678901234567890"
routing_number = "021000021"
iban_number = "GB82 WEST 1234 5698 7654 32"

# Financial patterns in different contexts
def banking_info():
    account_num = "9876543210123456789"
    routing = "026009593"
    swift_code = "CHASUS33"
    return validate_account(account_num, routing)

class BankAccount:
    def __init__(self):
        self.account_number = "55667788990011223344"
        self.routing_number = "111000025"
        self.iban = "DE89 3704 0044 0532 0130 00"
        self.bic = "COBADEFFXXX"
    
    def transfer_funds(self):
        # Source account: 11223344556677889900
        target_account = "99887766554433221100"
        return process_transfer(target_account)

# Financial validation patterns
FINANCIAL_DATA = [
    "12345678901234567890",  # Account number
    "021000021",             # Routing number  
    "GB82 WEST 1234 5698 7654 32",  # IBAN
    "CHASUS33"               # SWIFT code
]

# Financial data in context
def process_payments():
    """
    Account: 1234567890123456
    Routing: 021000021
    IBAN: FR14 2004 1010 0505 0001 3M02 606
    """
    payment_data = {
        "from_account": "55443322110099887766",
        "to_account": "99887766554433221100",
        "routing": "026009593"
    }
    return payment_data
'''
    
    @staticmethod
    def get_government_id_pii_file() -> str:
        """File with government ID PII patterns."""
        return '''
# Government ID PII patterns
drivers_license = "D123456789"
passport_number = "AB1234567"
tax_id = "12-3456789"

# Government ID patterns in different contexts
def verify_identity():
    dl_number = "DL987654321"
    passport = "CD9876543"
    ein = "98-7654321"
    return validate_documents(dl_number, passport)

class GovernmentID:
    def __init__(self):
        self.drivers_license = "DL-CA-A1234567"
        self.passport = "USA123456789"
        self.state_id = "ID-TX-987654321"
        self.tax_id = "TAX-55-4433221"
    
    def update_license(self):
        # Old DL: DL-NY-Z9876543
        new_dl = "DL-FL-B2468024"
        return new_dl

# Government ID validation patterns
GOVERNMENT_IDS = [
    "D123456789",      # Driver's License
    "AB1234567",       # Passport
    "12-3456789",      # Tax ID
    "ID987654321"      # State ID
]

# Government IDs in context
def citizenship_verification():
    """
    Driver's License: DL-CA-X1234567
    Passport: USA987654321
    Green Card: GC-A123456789
    """
    documents = {
        "license": "DL-TX-B9876543",
        "passport": "CD1122334455",
        "visa": "VISA-H1B-789012"
    }
    return documents
'''
    
    @staticmethod
    def get_mixed_pii_file() -> str:
        """File with mixed PII types for comprehensive testing."""
        return '''
# Mixed PII patterns for comprehensive testing
class PersonalInformation:
    """Class containing multiple PII types."""
    
    def __init__(self):
        # Contact information
        self.name = "John Doe"
        self.email = "john.doe@example.com"
        self.phone = "(555) 123-4567"
        self.address = "123 Main Street, Anytown, ST 12345"
        
        # Government IDs
        self.ssn = "123-45-6789"
        self.drivers_license = "D123456789"
        self.passport = "AB1234567"
        
        # Financial information
        self.credit_card = "4532-1234-5678-9012"
        self.bank_account = "12345678901234567890"
        self.routing_number = "021000021"
        
        # Medical information
        self.patient_id = "P123456789"
        self.insurance_id = "INS-ABC123456"
    
    def to_dict(self):
        """Convert to dictionary - exposes all PII."""
        return {
            "personal": {
                "email": "jane.smith@company.com",
                "phone": "555-987-6543",
                "ssn": "987-65-4321"
            },
            "financial": {
                "card": "5555-4444-3333-2222",
                "account": "9876543210987654321",
                "routing": "026009593"
            },
            "medical": {
                "patient": "P987654321",
                "mrn": "MR-2023-567890"
            }
        }

# PII in various data structures
EMPLOYEE_DATA = {
    "employees": [
        {
            "id": 1,
            "email": "alice@company.com",
            "phone": "555-111-2222",
            "ssn": "111-22-3333"
        },
        {
            "id": 2, 
            "email": "bob@company.com",
            "phone": "(555) 444-5555",
            "ssn": "444-55-6666"
        }
    ]
}

def process_customer_data():
    """Function processing multiple PII types."""
    customers = [
        {
            "name": "Customer One",
            "contact": "customer1@email.com",
            "phone": "555-777-8888",
            "payment": "4111-1111-1111-1111",
            "address": "456 Customer Lane, City, ST 67890"
        },
        {
            "name": "Customer Two", 
            "contact": "customer2@email.com",
            "phone": "(555) 999-0000",
            "payment": "5105-1051-0510-5100",
            "ssn": "777-88-9999"
        }
    ]
    return customers
'''
    
    @staticmethod
    def create_privacy_test_project(base_dir: Path) -> Dict[str, Path]:
        """Create a complete test project with privacy/PII issues."""
        files = {}
        
        # Create privacy test files
        test_files = {
            'email_pii.py': PrivacyTestFiles.get_email_pii_file(),
            'ssn_pii.py': PrivacyTestFiles.get_ssn_pii_file(),
            'phone_pii.py': PrivacyTestFiles.get_phone_pii_file(),
            'credit_card_pii.py': PrivacyTestFiles.get_credit_card_pii_file(),
            'address_pii.py': PrivacyTestFiles.get_address_pii_file(),
            'medical_pii.py': PrivacyTestFiles.get_medical_pii_file(),
            'financial_pii.py': PrivacyTestFiles.get_financial_pii_file(),
            'government_id_pii.py': PrivacyTestFiles.get_government_id_pii_file(),
            'mixed_pii.py': PrivacyTestFiles.get_mixed_pii_file(),
        }
        
        for filename, content in test_files.items():
            file_path = base_dir / filename
            file_path.write_text(content)
            files[filename] = file_path
        
        return files
    
    @staticmethod
    def get_expected_pii_findings() -> Dict[str, List[str]]:
        """Get expected PII findings for each test file."""
        return {
            'email_pii.py': [
                'Email address detected',
                'PII: Email',
                'Contact information exposed'
            ],
            'ssn_pii.py': [
                'Social Security Number detected',
                'PII: SSN', 
                'Government identifier exposed'
            ],
            'phone_pii.py': [
                'Phone number detected',
                'PII: Phone',
                'Contact information exposed'
            ],
            'credit_card_pii.py': [
                'Credit card number detected',
                'PII: Credit Card',
                'Financial information exposed'
            ],
            'address_pii.py': [
                'Address information detected',
                'PII: Address',
                'Location information exposed'
            ],
            'medical_pii.py': [
                'Medical record number detected',
                'PII: Medical',
                'Health information exposed'
            ],
            'financial_pii.py': [
                'Bank account number detected',
                'PII: Financial',
                'Banking information exposed'
            ],
            'government_id_pii.py': [
                'Government ID detected',
                'PII: Government ID',
                'Official identifier exposed'
            ],
            'mixed_pii.py': [
                'Multiple PII types detected',
                'Comprehensive data exposure',
                'Mixed personal information'
            ]
        }