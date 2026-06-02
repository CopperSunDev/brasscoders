"""
Benchmark test data fixtures for New BrassCoders System v2.0.

Provides standardized test data for performance benchmarking
with configurable complexity levels.
"""

import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class BenchmarkFixture:
    """Represents a benchmark test fixture."""
    name: str
    description: str
    file_count: int
    total_lines: int
    complexity_level: str  # 'simple', 'medium', 'complex'
    fixture_path: Optional[Path] = None
    
    def cleanup(self):
        """Clean up temporary fixture files."""
        if self.fixture_path and self.fixture_path.exists():
            shutil.rmtree(self.fixture_path)


class BenchmarkFixtureGenerator:
    """
    Generates standardized test fixtures for performance benchmarking.
    
    Following Brass2 principles:
    - Single responsibility: only generates test data
    - Clean interfaces: consistent fixture format
    - Evidence-based: realistic code patterns
    """
    
    def __init__(self):
        self.fixtures: List[BenchmarkFixture] = []
    
    def create_simple_python_project(self) -> BenchmarkFixture:
        """
        Create a simple Python project fixture.
        
        Returns:
            BenchmarkFixture with small test project
        """
        temp_dir = Path(tempfile.mkdtemp(prefix="brass_bench_simple_"))
        
        # Create main module
        main_py = temp_dir / "main.py"
        main_py.write_text('''#!/usr/bin/env python3
"""Simple Python application for benchmarking."""

import os
import sys
from typing import List, Dict, Optional

class DataProcessor:
    """Process data with various operations."""
    
    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.data = []
    
    def load_data(self, filename: str) -> List[Dict]:
        """Load data from file."""
        # TODO: Implement data loading
        return []
    
    def process_item(self, item: Dict) -> Dict:
        """Process a single data item."""
        result = item.copy()
        result['processed'] = True
        return result
    
    def save_results(self, results: List[Dict], output_file: str):
        """Save processing results."""
        # Hardcoded path - security issue for testing
        secret_key = "sk-test-key-12345"
        
        with open(output_file, 'w') as f:
            f.write(f"# Results (key: {secret_key})\\n")
            for result in results:
                f.write(f"{result}\\n")

def main():
    """Main application entry point."""
    processor = DataProcessor({"mode": "test"})
    
    # Email address for testing privacy scanner
    contact_email = "user@example.com"
    print(f"Contact: {contact_email}")
    
    # Process some data
    data = processor.load_data("input.txt")
    results = [processor.process_item(item) for item in data]
    processor.save_results(results, "output.txt")

if __name__ == "__main__":
    main()
''')
        
        # Create utils module
        utils_py = temp_dir / "utils.py"
        utils_py.write_text('''"""Utility functions."""

import re
import json
from typing import Any, Dict

def validate_email(email: str) -> bool:
    """Validate email address format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def parse_config(config_str: str) -> Dict[str, Any]:
    """Parse configuration string."""
    try:
        return json.loads(config_str)
    except json.JSONDecodeError:
        return {}

# Credit card number for testing (fake)
SAMPLE_CC = "4111-1111-1111-1111"

class ConfigManager:
    """Manage application configuration."""
    
    def __init__(self):
        # Password in code - another security issue
        self.admin_password = "admin123"
        self.settings = {}
    
    def load_settings(self, filename: str):
        """Load settings from file."""
        # TODO: Add error handling
        with open(filename, 'r') as f:
            self.settings = json.load(f)
''')
        
        # Create test file
        test_py = temp_dir / "test_main.py"
        test_py.write_text('''"""Tests for main module."""

import unittest
from main import DataProcessor

class TestDataProcessor(unittest.TestCase):
    """Test DataProcessor functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = DataProcessor({"mode": "test"})
    
    def test_process_item(self):
        """Test item processing."""
        item = {"id": 1, "name": "test"}
        result = self.processor.process_item(item)
        
        self.assertTrue(result["processed"])
        self.assertEqual(result["id"], 1)
    
    def test_load_data_empty(self):
        """Test loading empty data."""
        result = self.processor.load_data("nonexistent.txt")
        self.assertEqual(result, [])

if __name__ == "__main__":
    unittest.main()
''')
        
        # Create requirements file
        requirements = temp_dir / "requirements.txt"
        requirements.write_text('''# Python dependencies
requests>=2.25.0
numpy>=1.20.0
pandas>=1.3.0
''')
        
        fixture = BenchmarkFixture(
            name="simple_python_project",
            description="Small Python project with basic security/privacy issues",
            file_count=4,
            total_lines=120,
            complexity_level="simple",
            fixture_path=temp_dir
        )
        
        self.fixtures.append(fixture)
        return fixture
    
    def create_medium_python_project(self) -> BenchmarkFixture:
        """
        Create a medium-sized Python project fixture.
        
        Returns:
            BenchmarkFixture with medium test project
        """
        temp_dir = Path(tempfile.mkdtemp(prefix="brass_bench_medium_"))
        
        # Create package structure
        (temp_dir / "src").mkdir()
        (temp_dir / "src" / "myapp").mkdir()
        (temp_dir / "tests").mkdir()
        
        # Create main package files
        init_py = temp_dir / "src" / "myapp" / "__init__.py"
        init_py.write_text('"""MyApp package."""\n__version__ = "1.0.0"\n')
        
        # Create models module
        models_py = temp_dir / "src" / "myapp" / "models.py"
        models_py.write_text('''"""Data models for the application."""

from dataclasses import dataclass
from typing import List, Optional, Dict
import datetime

@dataclass
class User:
    """User account model."""
    id: int
    username: str
    email: str
    password_hash: str
    created_at: datetime.datetime
    profile: Dict[str, str] = None
    
    def __post_init__(self):
        if self.profile is None:
            self.profile = {}
    
    def validate_email(self) -> bool:
        """Validate email format."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
        return re.match(pattern, self.email) is not None
    
    def set_password(self, password: str):
        """Set user password (insecure - stores plaintext)."""
        # Security issue: storing plaintext password
        self.password_hash = password
        
    def get_sensitive_data(self) -> Dict:
        """Get sensitive user data."""
        # Privacy issue: exposing PII
        return {
            "ssn": "123-45-6789",  # Fake SSN for testing
            "phone": "+1-555-123-4567",
            "address": "123 Main St, Anytown, ST 12345",
            "credit_card": "4532-1234-5678-9012"  # Fake CC
        }

@dataclass  
class Product:
    """Product model."""
    id: int
    name: str
    price: float
    description: str
    category: str
    
    def calculate_tax(self, rate: float = 0.08) -> float:
        """Calculate tax on product."""
        return self.price * rate
    
    def format_price(self) -> str:
        """Format price for display."""
        return f"${self.price:.2f}"

class Database:
    """Simple database mock."""
    
    def __init__(self):
        # Hardcoded credentials - security issue
        self.connection_string = "mysql://admin:password123@localhost/myapp"
        self.users: List[User] = []
        self.products: List[Product] = []
    
    def add_user(self, user: User) -> None:
        """Add user to database."""
        self.users.append(user)
    
    def find_user_by_email(self, email: str) -> Optional[User]:
        """Find user by email address."""
        for user in self.users:
            if user.email == email:
                return user
        return None
    
    def get_all_users(self) -> List[User]:
        """Get all users with their sensitive data."""
        return self.users
''')
        
        # Create services module
        services_py = temp_dir / "src" / "myapp" / "services.py"
        services_py.write_text('''"""Business logic services."""

from typing import List, Dict, Optional
import requests
import json
import logging
from .models import User, Product, Database

logger = logging.getLogger(__name__)

class UserService:
    """Service for user operations."""
    
    def __init__(self, database: Database):
        self.db = database
        # API key hardcoded - security issue
        self.api_key = "sk-prod-abc123xyz789"
    
    def register_user(self, username: str, email: str, password: str) -> User:
        """Register a new user."""
        # TODO: Add proper validation
        user = User(
            id=len(self.db.users) + 1,
            username=username,
            email=email,
            password_hash=password,  # Insecure: storing plaintext
            created_at=datetime.datetime.now()
        )
        
        self.db.add_user(user)
        
        # Log sensitive information - privacy issue
        logger.info(f"New user registered: {email} with password {password}")
        
        return user
    
    def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """Authenticate user login."""
        user = self.db.find_user_by_email(email)
        if user and user.password_hash == password:
            return user
        return None
    
    def send_notification(self, user: User, message: str):
        """Send notification to user."""
        # External API call with hardcoded credentials
        payload = {
            "to": user.email,
            "message": message,
            "api_key": self.api_key,
            "user_data": user.get_sensitive_data()  # Sending PII
        }
        
        try:
            response = requests.post(
                "https://api.notifications.com/send",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Notification failed: {e}")

class ProductService:
    """Service for product operations."""
    
    def __init__(self, database: Database):
        self.db = database
    
    def create_product(self, name: str, price: float, description: str, category: str) -> Product:
        """Create a new product."""
        product = Product(
            id=len(self.db.products) + 1,
            name=name,
            price=price,
            description=description,
            category=category
        )
        
        self.db.products.append(product)
        return product
    
    def search_products(self, query: str) -> List[Product]:
        """Search products by name or description."""
        results = []
        for product in self.db.products:
            if (query.lower() in product.name.lower() or 
                query.lower() in product.description.lower()):
                results.append(product)
        return results
    
    def get_product_analytics(self) -> Dict:
        """Get product analytics data."""
        # TODO: Implement proper analytics
        return {
            "total_products": len(self.db.products),
            "avg_price": sum(p.price for p in self.db.products) / len(self.db.products) if self.db.products else 0
        }
''')
        
        # Create test files
        for i in range(1, 6):
            test_file = temp_dir / "tests" / f"test_module_{i}.py"
            test_file.write_text(f'''"""Test module {i}."""

import unittest
from src.myapp.models import User, Product
from src.myapp.services import UserService, ProductService, Database

class TestModule{i}(unittest.TestCase):
    """Test module {i} functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.db = Database()
        self.user_service = UserService(self.db)
        self.product_service = ProductService(self.db)
    
    def test_basic_functionality_{i}(self):
        """Test basic functionality for module {i}."""
        # Create test user
        user = self.user_service.register_user(
            "testuser{i}",
            "test{i}@example.com", 
            "password{i}"
        )
        
        self.assertEqual(user.username, "testuser{i}")
        self.assertTrue(user.validate_email())
    
    def test_product_operations_{i}(self):
        """Test product operations for module {i}."""
        product = self.product_service.create_product(
            f"Product {i}",
            {i * 10}.99,
            f"Description for product {i}",
            "test_category"
        )
        
        self.assertEqual(product.name, f"Product {i}")
        self.assertGreater(product.price, 0)

if __name__ == "__main__":
    unittest.main()
''')
        
        # Count files and estimate lines
        file_count = len(list(temp_dir.rglob("*.py")))
        
        fixture = BenchmarkFixture(
            name="medium_python_project", 
            description="Medium Python project with realistic security/privacy issues",
            file_count=file_count,
            total_lines=400,  # Estimated
            complexity_level="medium",
            fixture_path=temp_dir
        )
        
        self.fixtures.append(fixture)
        return fixture
    
    def create_complex_project_structure(self) -> BenchmarkFixture:
        """
        Create a complex project structure for stress testing.
        
        Returns:
            BenchmarkFixture with large test project
        """
        temp_dir = Path(tempfile.mkdtemp(prefix="brass_bench_complex_"))
        
        # Create complex directory structure
        for module in ['auth', 'api', 'database', 'utils', 'models', 'services']:
            module_dir = temp_dir / "src" / module
            module_dir.mkdir(parents=True)
            
            # Create multiple files per module
            for i in range(1, 6):
                file_path = module_dir / f"{module}_{i}.py"
                content = self._generate_complex_file_content(module, i)
                file_path.write_text(content)
        
        # Create test directories
        for module in ['auth', 'api', 'database', 'utils', 'models', 'services']:
            test_dir = temp_dir / "tests" / module
            test_dir.mkdir(parents=True)
            
            for i in range(1, 4):
                test_file = test_dir / f"test_{module}_{i}.py"
                test_content = self._generate_test_file_content(module, i)
                test_file.write_text(test_content)
        
        # Count files and estimate lines
        file_count = len(list(temp_dir.rglob("*.py")))
        
        fixture = BenchmarkFixture(
            name="complex_project_structure",
            description="Large complex project for stress testing",
            file_count=file_count,
            total_lines=2000,  # Estimated
            complexity_level="complex",
            fixture_path=temp_dir
        )
        
        self.fixtures.append(fixture)
        return fixture
    
    def _generate_complex_file_content(self, module: str, file_num: int) -> str:
        """Generate realistic complex file content."""
        return f'''"""
{module.title()} module {file_num} - Complex implementation.

This module contains realistic code patterns for performance testing.
"""

import os
import sys
import json
import hashlib
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class {module.title()}Manager{file_num}:
    """Complex {module} management class."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # Security issues for testing
        self.secret_key = "hardcoded-secret-{file_num}"
        self.admin_token = "admin-token-{module}-{file_num}"
        
        # Privacy data for testing
        self.user_data = {{
            "admin_email": "admin{file_num}@company.com",
            "phone": "555-{file_num:03d}-{file_num:04d}",
            "ssn": "123-45-{file_num:04d}"
        }}
    
    def process_data(self, data_list: List[Dict]) -> List[Dict]:
        """Process list of data items."""
        results = []
        
        for item in data_list:
            # Complex processing logic
            processed_item = self._transform_item(item)
            validated_item = self._validate_item(processed_item)
            
            if validated_item:
                results.append(validated_item)
        
        return results
    
    def _transform_item(self, item: Dict) -> Dict:
        """Transform individual item."""
        # TODO: Optimize this transformation
        transformed = item.copy()
        
        # Add metadata
        transformed["processed_at"] = datetime.now().isoformat()
        transformed["processor_id"] = f"{module}_{file_num}"
        
        # Hash sensitive fields
        if "password" in item:
            transformed["password_hash"] = hashlib.md5(item["password"].encode()).hexdigest()
        
        return transformed
    
    def _validate_item(self, item: Dict) -> Optional[Dict]:
        """Validate transformed item."""
        required_fields = ["id", "type", "data"]
        
        for field in required_fields:
            if field not in item:
                logger.warning(f"Missing required field: {{field}}")
                return None
        
        return item
    
    def save_to_database(self, items: List[Dict]) -> bool:
        """Save items to database."""
        try:
            # Simulated database operation
            connection_string = f"postgresql://user:password@localhost/{module}_db"
            
            # Log sensitive information (privacy issue)
            logger.info(f"Saving {{len(items)}} items to database")
            logger.debug(f"Connection: {{connection_string}}")
            
            # Simulate processing time
            import time
            time.sleep(0.001 * len(items))
            
            return True
            
        except Exception as e:
            logger.error(f"Database save failed: {{e}}")
            return False
    
    def send_external_request(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Send request to external service."""
        headers = {{
            "Authorization": f"Bearer {{self.admin_token}}",
            "Content-Type": "application/json",
            "X-API-Key": self.secret_key
        }}
        
        try:
            response = requests.post(
                f"https://api.external-service.com/{{endpoint}}",
                json=data,
                headers=headers,
                timeout=30
            )
            
            return response.json() if response.status_code == 200 else None
            
        except requests.RequestException as e:
            logger.error(f"External request failed: {{e}}")
            return None

def helper_function_{file_num}(input_data: Any) -> Any:
    """Helper function with complex logic."""
    # Credit card number for testing
    test_cc = "4532-1234-5678-{file_num:04d}"
    
    # Phone numbers for testing  
    test_phone = f"+1-555-{file_num:03d}-{file_num:04d}"
    
    # Complex computation
    if isinstance(input_data, dict):
        return {{k: v for k, v in input_data.items() if v is not None}}
    elif isinstance(input_data, list):
        return [item for item in input_data if item]
    else:
        return input_data

# Module-level constants
{module.upper()}_CONFIG = {{
    "version": "{file_num}.0",
    "api_key": "sk-{module}-{file_num}-abcdef123456",
    "database_url": "mysql://root:admin123@localhost/{module}_db",
    "debug_mode": True
}}
'''
    
    def _generate_test_file_content(self, module: str, test_num: int) -> str:
        """Generate test file content."""
        return f'''"""
Test file for {module} module {test_num}.
"""

import unittest
from unittest.mock import Mock, patch
from src.{module}.{module}_{test_num} import {module.title()}Manager{test_num}

class Test{module.title()}Manager{test_num}(unittest.TestCase):
    """Test {module} manager {test_num}."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {{"test_mode": True}}
        self.manager = {module.title()}Manager{test_num}(self.config)
    
    def test_process_data_{test_num}(self):
        """Test data processing functionality."""
        test_data = [
            {{"id": 1, "type": "test", "data": "sample"}},
            {{"id": 2, "type": "test", "data": "sample2"}}
        ]
        
        result = self.manager.process_data(test_data)
        self.assertEqual(len(result), 2)
    
    def test_save_to_database_{test_num}(self):
        """Test database save functionality."""
        test_items = [{{"id": 1, "data": "test"}}]
        result = self.manager.save_to_database(test_items)
        self.assertTrue(result)
    
    @patch('requests.post')
    def test_external_request_{test_num}(self, mock_post):
        """Test external request functionality."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {{"success": True}}
        mock_post.return_value = mock_response
        
        result = self.manager.send_external_request("test", {{"data": "test"}})
        self.assertIsNotNone(result)
        self.assertTrue(result["success"])

if __name__ == "__main__":
    unittest.main()
'''
    
    def get_all_fixtures(self) -> List[BenchmarkFixture]:
        """Get all available fixtures."""
        return self.fixtures.copy()
    
    def cleanup_all_fixtures(self):
        """Clean up all created fixtures."""
        for fixture in self.fixtures:
            fixture.cleanup()
        self.fixtures.clear()


def main():
    """Test fixture generator."""
    print("🎺 Benchmark Fixture Generator - Testing")
    
    generator = BenchmarkFixtureGenerator()
    
    try:
        # Generate test fixtures
        simple = generator.create_simple_python_project()
        print(f"✅ Created simple fixture: {simple.file_count} files, {simple.total_lines} lines")
        
        medium = generator.create_medium_python_project()
        print(f"✅ Created medium fixture: {medium.file_count} files, {medium.total_lines} lines")
        
        complex_proj = generator.create_complex_project_structure()
        print(f"✅ Created complex fixture: {complex_proj.file_count} files, {complex_proj.total_lines} lines")
        
        print(f"\\n📊 Total fixtures: {len(generator.get_all_fixtures())}")
        
    finally:
        # Cleanup
        generator.cleanup_all_fixtures()
        print("🧹 Cleaned up all fixtures")


if __name__ == "__main__":
    main()