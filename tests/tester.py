import os
import ctypes

def check_root_mode():
    """
    Check if the script is being executed in root mode
    
    Return:
    False if the user is not root. True in the other case
    """
    
    try:
        is_root = os.getuid() == 0
    except AttributeError:
        is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    return is_root
