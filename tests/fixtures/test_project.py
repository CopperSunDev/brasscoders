"""
Test fixture - a Python file with various issues for testing.
"""

import os
import sys

# TODO: Add proper error handling
def complex_function(a, b, c, d, e, f):
    """This function has multiple issues for testing."""
    if a > 0:
        if b > 0:
            for i in range(10):
                if i % 2 == 0:
                    while c > 0:
                        try:
                            if c > 5:
                                for j in range(5):
                                    if j > 2:
                                        if d > 0:
                                            return True
                                        elif d < 0:
                                            return False
                                        else:
                                            continue
                                    else:
                                        pass
                            elif c > 3:
                                return False
                            else:
                                c -= 1
                        except:
                            pass  # FIXME: Empty except block
                else:
                    continue
        else:
            return None
    return False

def dangerous_function(user_input):
    """Function with security issues."""
    # Dangerous eval usage
    result = eval(user_input)
    
    # Dangerous exec usage  
    exec(user_input)
    
    return result

class LargeClass:
    """A class with too many methods."""
    
    def method1(self): pass
    def method2(self): pass  
    def method3(self): pass
    def method4(self): pass
    def method5(self): pass
    def method6(self): pass
    def method7(self): pass
    def method8(self): pass
    def method9(self): pass
    def method10(self): pass
    def method11(self): pass
    def method12(self): pass
    def method13(self): pass
    def method14(self): pass
    def method15(self): pass
    def method16(self): pass
    def method17(self): pass
    def method18(self): pass
    def method19(self): pass
    def method20(self): pass
    def method21(self): pass  # This puts it over the threshold

# HACK: This is a temporary workaround
def risky_operation():
    try:
        dangerous_operation()
    except:
        pass

# XXX: This needs review
def unused_function():
    pass