import pip

from distutils import spawn
from pip._internal.utils.misc import get_installed_distributions as get_pip_installations

class ConfigurationLoader:
    """
    Class used by NetwInv to check if all required utils are installed.
    """
    
    def __init__(self):
        pass
    
    def check_os_utils(self):
        """
        Checks if the O.S. needed utils are installed.
        """
        
        # Needed O.S. utils
        utils = ['nmap']
        
        for util in utils:
            # If util is not find, print an error message. If util is find, print a message.
            if spawn.find_executable(util) is None:
                print('ATENTION: ' + util + ' is not installed on your operating system. You need to install it and then run the application again')
            else:
                print(util + ' is installed')
                
    def check_pip_utils(self):
        """
        Checks if needed pip utils are installed.
        """
        
        # Needed pip utils
        pip_utils = ['python-nmap','pysnmp','netifaces','schedule','networkx','matplotlib','reportlab','configparser']
        
        # Get the installed utils
        installed_utils = get_pip_installations()
        # Get a sorted list with the pip utils
        installed_utils_list = sorted(['%s' % i.key for i in installed_utils])
        
        for util in pip_utils:
            # If util is not in the installed utils list, ask if the user want to install it.
            # If util is in the installed utils list, print a message.
            if util not in installed_utils_list:
                toret = ''
                
                while toret not in ['y','n','Y','N']:
                    print(util + ' was not found. Would you like to install this util? (y/n)')
                    answer = raw_input('Answer: ')
                
                # If answer is yes, install the util. If answer is no, print a message.
                if answer in ['y','Y']:
                    self.__install_util(util)
                else:
                    print('ATENTION: ' + util + 'needs tobe installed to run the application. Execute pip install ' + util + ' and then run the script again.')
            else:
                print('Found ' + util + ' package')
                
    def __install_util(self,util):
        """
        Install the indicated util.

            :param util: The util that should be installed
            :type util: str
        """
        
        try:
            if hasattr(pip,'main'):
                pip.main(['install',util])
            else:
                pip._internal.main(['install',util])
        except Exception as e:
            print('ATENTION: An error has been occured installing ' + util + '. Pleaser install it manually.')
            
        print(util + 'was installed succesfully. Please run again the application.')
        exit()
        
        
