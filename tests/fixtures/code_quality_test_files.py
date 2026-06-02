"""
Code quality test fixtures for New BrassCoders System v2.0.

Provides stable test data for code quality analysis testing.
"""

from pathlib import Path
from typing import Dict, List, Tuple


class CodeQualityTestFiles:
    """Code quality issue test files for consistent testing."""
    
    @staticmethod
    def get_complexity_issues_file() -> str:
        """File with high complexity and nested structures."""
        return '''
# High complexity and deeply nested structures
def overly_complex_function(a, b, c, d, e, f, g, h):
    """Function with excessive cyclomatic complexity."""
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    for i in range(10):
                        if i % 2 == 0:
                            for j in range(5):
                                if j > 2:
                                    while e > 0:
                                        if f > 5:
                                            for k in range(3):
                                                if g > k:
                                                    if h > 0:
                                                        return True
                                                    elif h < 0:
                                                        return False
                                                    else:
                                                        continue
                                                else:
                                                    break
                                        elif f > 3:
                                            return None
                                        else:
                                            e -= 1
                                else:
                                    pass
                        else:
                            continue
                else:
                    return False
            else:
                return None
        else:
            return -1
    else:
        return 0

def deeply_nested_conditional(x, y, z):
    """Function with excessive nesting depth."""
    if x:
        if y:
            if z:
                if x > y:
                    if y > z:
                        if x > 10:
                            if y > 5:
                                if z > 1:
                                    if x + y > z:
                                        if x * y > z:
                                            return "deeply nested result"
                                        else:
                                            return "alternate result"
                                    else:
                                        return "another result"
                                else:
                                    return "z too small"
                            else:
                                return "y too small"
                        else:
                            return "x too small"
                    else:
                        return "y not greater than z"
                else:
                    return "x not greater than y"
            else:
                return "z is falsy"
        else:
            return "y is falsy"
    else:
        return "x is falsy"

class ComplexClass:
    """Class with complex methods and high coupling."""
    
    def complex_calculation(self, data, config, options, metadata, context):
        """Method with complex logic and many parameters."""
        result = 0
        
        if config.enabled:
            if data:
                for item in data:
                    if item.valid:
                        if options.process_all:
                            for option in options.items:
                                if option.active:
                                    for meta in metadata:
                                        if meta.key == option.key:
                                            if context.allow_processing:
                                                if meta.value > context.threshold:
                                                    result += self._process_item(item, option, meta)
                                                else:
                                                    result += self._fallback_process(item)
                                            else:
                                                continue
                                        else:
                                            continue
                                else:
                                    continue
                        else:
                            result += self._simple_process(item)
                    else:
                        continue
            else:
                result = self._default_value()
        else:
            result = self._disabled_value()
        
        return result
'''
    
    @staticmethod
    def get_long_parameter_lists_file() -> str:
        """File with functions having too many parameters."""
        return '''
# Functions with excessive parameter counts
def function_with_many_params(a, b, c, d, e, f, g, h, i, j, k, l):
    """Function with too many parameters (12 > 10 threshold)."""
    return a + b + c + d + e + f + g + h + i + j + k + l

def another_long_param_function(param1, param2, param3, param4, param5, 
                               param6, param7, param8, param9, param10,
                               param11, param12, param13):
    """Another function with excessive parameters (13 > 10 threshold)."""
    result = param1 * param2
    if param3:
        result += param4 + param5 + param6
    else:
        result *= param7 + param8 + param9 + param10 + param11 + param12 + param13
    return result

class ClassWithLongMethods:
    """Class with methods having too many parameters."""
    
    def method_with_many_params(self, arg1, arg2, arg3, arg4, arg5, arg6, 
                               arg7, arg8, arg9, arg10, arg11):
        """Method with too many parameters (11 + self > 10 threshold)."""
        return self._process(arg1, arg2, arg3, arg4, arg5, arg6, 
                           arg7, arg8, arg9, arg10, arg11)
    
    def configuration_method(self, host, port, username, password, database,
                           timeout, retries, ssl_enabled, debug_mode,
                           connection_pool_size, max_connections, 
                           idle_timeout, query_timeout):
        """Configuration method with many parameters (13 + self > 10)."""
        config = {
            'host': host, 'port': port, 'username': username,
            'password': password, 'database': database,
            'timeout': timeout, 'retries': retries,
            'ssl_enabled': ssl_enabled, 'debug_mode': debug_mode,
            'connection_pool_size': connection_pool_size,
            'max_connections': max_connections,
            'idle_timeout': idle_timeout,
            'query_timeout': query_timeout
        }
        return config

def data_processing_function(input_data, output_format, compression_type,
                           encryption_key, validation_rules, error_handling,
                           logging_level, batch_size, parallel_processing,
                           memory_limit, disk_cache_size):
    """Data processing with many parameters (11 > 10 threshold)."""
    processor = DataProcessor(
        data=input_data,
        format=output_format, 
        compression=compression_type,
        encryption=encryption_key,
        validation=validation_rules,
        error_handler=error_handling,
        log_level=logging_level,
        batch_size=batch_size,
        parallel=parallel_processing,
        memory_limit=memory_limit,
        cache_size=disk_cache_size
    )
    return processor.process()
'''
    
    @staticmethod
    def get_large_classes_file() -> str:
        """File with classes having too many methods."""
        return '''
# Classes with too many methods (exceeding threshold)
class LargeUtilityClass:
    """Class with excessive number of methods (25+ methods)."""
    
    def method_01(self): return "method_01"
    def method_02(self): return "method_02"  
    def method_03(self): return "method_03"
    def method_04(self): return "method_04"
    def method_05(self): return "method_05"
    def method_06(self): return "method_06"
    def method_07(self): return "method_07"
    def method_08(self): return "method_08"
    def method_09(self): return "method_09"
    def method_10(self): return "method_10"
    def method_11(self): return "method_11"
    def method_12(self): return "method_12"
    def method_13(self): return "method_13"
    def method_14(self): return "method_14"
    def method_15(self): return "method_15"
    def method_16(self): return "method_16"
    def method_17(self): return "method_17"
    def method_18(self): return "method_18"
    def method_19(self): return "method_19"
    def method_20(self): return "method_20"
    def method_21(self): return "method_21"
    def method_22(self): return "method_22"
    def method_23(self): return "method_23"
    def method_24(self): return "method_24"
    def method_25(self): return "method_25"
    def method_26(self): return "method_26"  # Exceeds threshold
    def method_27(self): return "method_27"
    def method_28(self): return "method_28"

class OversizedDataProcessor:
    """Another class with too many methods."""
    
    def validate_input(self): pass
    def sanitize_data(self): pass
    def parse_json(self): pass
    def parse_xml(self): pass
    def parse_csv(self): pass
    def transform_data(self): pass
    def filter_data(self): pass
    def sort_data(self): pass
    def group_data(self): pass
    def aggregate_data(self): pass
    def format_output(self): pass
    def save_to_file(self): pass
    def save_to_database(self): pass
    def send_to_api(self): pass
    def generate_report(self): pass
    def create_summary(self): pass
    def log_processing(self): pass
    def handle_errors(self): pass
    def validate_results(self): pass
    def compress_output(self): pass
    def encrypt_data(self): pass
    def create_backup(self): pass
    def cleanup_temp_files(self): pass
    def send_notifications(self): pass
    def update_statistics(self): pass
    def archive_data(self): pass  # Method 26, exceeds threshold

class MonolithicManager:
    """Monolithic class trying to do everything."""
    
    # User management methods
    def create_user(self): pass
    def update_user(self): pass
    def delete_user(self): pass
    def authenticate_user(self): pass
    def authorize_user(self): pass
    
    # Data management methods
    def create_record(self): pass
    def read_record(self): pass
    def update_record(self): pass
    def delete_record(self): pass
    def search_records(self): pass
    
    # File management methods
    def upload_file(self): pass
    def download_file(self): pass
    def delete_file(self): pass
    def list_files(self): pass
    def compress_files(self): pass
    
    # Communication methods
    def send_email(self): pass
    def send_sms(self): pass
    def send_notification(self): pass
    def log_message(self): pass
    def broadcast_message(self): pass
    
    # Reporting methods
    def generate_user_report(self): pass
    def generate_data_report(self): pass
    def generate_file_report(self): pass
    def export_to_pdf(self): pass
    def export_to_excel(self): pass
    
    # System methods
    def backup_system(self): pass
    def restore_system(self): pass  # Method 27, well over threshold
'''
    
    @staticmethod
    def get_empty_exception_handlers_file() -> str:
        """File with empty exception handling blocks."""
        return '''
# Empty exception handling blocks
def risky_operation_1():
    """Function with empty except block."""
    try:
        dangerous_operation()
    except:
        pass  # Empty exception handler

def risky_operation_2():
    """Function with multiple empty exception handlers."""
    try:
        first_operation()
    except ValueError:
        pass  # Empty specific exception handler
    except Exception:
        pass  # Empty general exception handler

def file_operation():
    """File operation with empty exception handling."""
    try:
        with open('nonexistent.txt', 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        pass  # Empty file not found handler
    except IOError:
        pass  # Empty IO error handler

class DatabaseManager:
    """Class with multiple empty exception handlers."""
    
    def connect(self):
        """Database connection with empty exception handling."""
        try:
            self.connection = create_connection()
        except ConnectionError:
            pass  # Empty connection error handler
    
    def execute_query(self, query):
        """Query execution with empty exception handling.""" 
        try:
            return self.connection.execute(query)
        except:
            pass  # Empty general exception handler
    
    def close_connection(self):
        """Close connection with empty exception handling."""
        try:
            self.connection.close()
        except AttributeError:
            pass  # Empty attribute error handler
        except:
            pass  # Another empty exception handler

def network_request():
    """Network request with nested empty exception handling."""
    for attempt in range(3):
        try:
            response = make_request()
            return response
        except TimeoutError:
            try:
                backup_response = make_backup_request()
                return backup_response
            except:
                pass  # Nested empty exception handler
        except ConnectionError:
            pass  # Empty connection error handler
        except:
            pass  # Empty general exception handler

def data_processing():
    """Data processing with empty exception in loop."""
    results = []
    for item in data_items:
        try:
            processed = process_item(item)
            results.append(processed)
        except:
            pass  # Empty exception handler in loop
    return results
'''
    
    @staticmethod
    def get_todo_comments_file() -> str:
        """File with various TODO/FIXME/HACK comments."""
        return '''
# TODO: Implement proper error handling
def incomplete_function():
    """Function that needs completion."""
    pass

# FIXME: This function has a logic error
def broken_calculation(x, y):
    """Function with known issues."""
    # FIXME: Division by zero not handled
    return x / y

# XXX: This is a temporary hack
def temporary_workaround():
    """Temporary solution that needs refactoring."""
    # XXX: Replace with proper implementation
    global_variable = "hack"
    return global_variable

# HACK: Quick fix for deployment
def deployment_hack():
    """Quick fix that needs proper solution."""
    # HACK: Hardcoded values for now
    return {"status": "ok", "version": "1.0.0"}

class IncompleteClass:
    """Class with various completion markers."""
    
    def __init__(self):
        # TODO: Add proper initialization
        self.data = None
    
    def process_data(self):
        """Method that needs implementation."""
        # TODO: Implement data processing logic
        # FIXME: Handle edge cases
        # XXX: This is placeholder code
        if self.data:
            return "processed"
        else:
            return "no data"
    
    def validate_input(self, input_data):
        """Input validation method."""
        # FIXME: Add comprehensive validation
        # TODO: Support different input types
        return True  # XXX: Always returns True for now

def feature_in_development():
    """Feature still under development."""
    # TODO: Implement feature X
    # TODO: Add unit tests
    # TODO: Update documentation
    # FIXME: Handle error conditions
    # FIXME: Optimize performance
    print("Feature not implemented")

# NOTE: The following function needs review
def needs_review():
    """Function marked for review."""
    # NOTE: Check algorithm efficiency
    # REVIEW: Verify input validation
    # OPTIMIZE: Can this be made faster?
    return calculate_result()

# WARNING: This function modifies global state
def dangerous_global_modifier():
    """Function with warning about side effects."""
    # WARNING: Modifies global variables
    # CAUTION: Thread safety not guaranteed
    global shared_state
    shared_state += 1

def multiple_todos():
    """Function with multiple TODO items."""
    # TODO: Add logging
    # TODO: Add metrics collection
    # TODO: Add retry logic
    # TODO: Add timeout handling
    # TODO: Add input sanitization
    result = perform_operation()
    return result
'''
    
    @staticmethod
    def get_long_functions_file() -> str:
        """File with excessively long functions."""
        return '''
# Excessively long functions (over line limits)
def massive_function():
    """Function that is way too long (100+ lines)."""
    # Initialize variables
    result = 0
    counter = 0
    data_list = []
    error_count = 0
    
    # Step 1: Data preparation
    print("Starting data preparation")
    for i in range(100):
        if i % 2 == 0:
            data_list.append(i * 2)
        else:
            data_list.append(i * 3)
        counter += 1
    
    # Step 2: Data validation
    print("Validating data")
    valid_items = []
    for item in data_list:
        if item > 0:
            if item < 1000:
                if item % 5 == 0:
                    valid_items.append(item)
                else:
                    print(f"Item {item} not divisible by 5")
            else:
                print(f"Item {item} too large")
                error_count += 1
        else:
            print(f"Item {item} is not positive")
            error_count += 1
    
    # Step 3: Data processing
    print("Processing valid data")
    processed_items = []
    for item in valid_items:
        processed_value = item * 2
        if processed_value > 100:
            processed_value = processed_value / 2
        if processed_value < 50:
            processed_value = processed_value + 10
        processed_items.append(processed_value)
        result += processed_value
    
    # Step 4: Statistical analysis
    print("Performing statistical analysis")
    if processed_items:
        average = sum(processed_items) / len(processed_items)
        maximum = max(processed_items)
        minimum = min(processed_items)
        
        print(f"Average: {average}")
        print(f"Maximum: {maximum}")
        print(f"Minimum: {minimum}")
        
        # Calculate variance
        variance = sum((x - average) ** 2 for x in processed_items) / len(processed_items)
        print(f"Variance: {variance}")
        
        # Calculate standard deviation
        std_dev = variance ** 0.5
        print(f"Standard deviation: {std_dev}")
    
    # Step 5: Report generation
    print("Generating report")
    report = {
        'total_items': len(data_list),
        'valid_items': len(valid_items),
        'processed_items': len(processed_items),
        'error_count': error_count,
        'result': result
    }
    
    # Step 6: Cleanup and finalization
    print("Cleaning up")
    data_list.clear()
    valid_items.clear()
    processed_items.clear()
    
    # Step 7: Final validation
    if report['error_count'] > 10:
        print("Too many errors encountered")
        return None
    
    if report['processed_items'] == 0:
        print("No items were processed")
        return None
    
    # Step 8: Success logging
    print("Function completed successfully")
    print(f"Processed {report['processed_items']} items")
    print(f"Final result: {result}")
    
    return report
    # This function is now over 100 lines - too long!

def another_massive_function(config, data, options):
    """Another excessively long function."""
    # Initialization phase
    initialized = False
    result_data = {}
    processing_errors = []
    
    # Configuration validation
    if not config:
        raise ValueError("Configuration is required")
    
    if 'server' not in config:
        config['server'] = 'localhost'
    
    if 'port' not in config:
        config['port'] = 8080
    
    if 'timeout' not in config:
        config['timeout'] = 30
        
    # Data validation
    if not data:
        return {"error": "No data provided"}
    
    if not isinstance(data, list):
        data = [data]
    
    # Options processing
    if options is None:
        options = {}
    
    if 'verbose' not in options:
        options['verbose'] = False
    
    if 'debug' not in options:
        options['debug'] = False
    
    # Main processing loop
    for index, item in enumerate(data):
        try:
            if options['verbose']:
                print(f"Processing item {index}: {item}")
            
            # Item validation
            if not item:
                processing_errors.append(f"Empty item at index {index}")
                continue
            
            # Item processing
            processed_item = {}
            
            if 'id' in item:
                processed_item['id'] = item['id']
            else:
                processed_item['id'] = index
            
            if 'name' in item:
                processed_item['name'] = item['name'].strip()
            else:
                processed_item['name'] = f"Item_{index}"
            
            if 'value' in item:
                try:
                    processed_item['value'] = float(item['value'])
                except ValueError:
                    processing_errors.append(f"Invalid value for item {index}")
                    processed_item['value'] = 0.0
            else:
                processed_item['value'] = 0.0
            
            # Store processed item
            result_data[processed_item['id']] = processed_item
            
        except Exception as e:
            processing_errors.append(f"Error processing item {index}: {str(e)}")
            if options['debug']:
                import traceback
                traceback.print_exc()
    
    # Post-processing validation
    if not result_data:
        return {"error": "No items were successfully processed"}
    
    # Generate summary
    summary = {
        'total_input_items': len(data),
        'successfully_processed': len(result_data),
        'processing_errors': len(processing_errors),
        'error_rate': len(processing_errors) / len(data) if data else 0
    }
    
    # Final result assembly
    final_result = {
        'data': result_data,
        'summary': summary,
        'errors': processing_errors,
        'config_used': config,
        'options_used': options
    }
    
    return final_result
    # This function is also over 100 lines - too long!
'''
    
    @staticmethod
    def create_code_quality_test_project(base_dir: Path) -> Dict[str, Path]:
        """Create a complete test project with code quality issues."""
        files = {}
        
        # Create code quality test files
        test_files = {
            'complexity_issues.py': CodeQualityTestFiles.get_complexity_issues_file(),
            'long_parameter_lists.py': CodeQualityTestFiles.get_long_parameter_lists_file(),
            'large_classes.py': CodeQualityTestFiles.get_large_classes_file(),
            'empty_exception_handlers.py': CodeQualityTestFiles.get_empty_exception_handlers_file(),
            'todo_comments.py': CodeQualityTestFiles.get_todo_comments_file(),
            'long_functions.py': CodeQualityTestFiles.get_long_functions_file(),
        }
        
        for filename, content in test_files.items():
            file_path = base_dir / filename
            file_path.write_text(content)
            files[filename] = file_path
        
        return files
    
    @staticmethod
    def get_expected_quality_findings() -> Dict[str, List[str]]:
        """Get expected code quality findings for each test file."""
        return {
            'complexity_issues.py': [
                'High cyclomatic complexity',
                'Excessive nesting depth',
                'Complex conditional logic'
            ],
            'long_parameter_lists.py': [
                'Too many parameters',
                'Function parameter count exceeded',
                'Method signature too complex'
            ],
            'large_classes.py': [
                'Class has too many methods',
                'Excessive class size',  
                'Monolithic class structure'
            ],
            'empty_exception_handlers.py': [
                'Empty exception handler',
                'Exception caught but not handled',
                'Silent exception swallowing'
            ],
            'todo_comments.py': [
                'TODO comment found',
                'FIXME comment found',
                'XXX comment found',
                'HACK comment found'
            ],
            'long_functions.py': [
                'Function too long',
                'Excessive function length',
                'Function exceeds line limit'
            ]
        }