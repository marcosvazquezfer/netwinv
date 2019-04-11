import argparse
import pip

from distutils import spawn
from pip._internal.utils.misc import get_installed_distributions as get_pip_installations

class ConfigurationLoader:
    '''
    COMENTAR
    '''
    
    def __init__(self):
        pass
    
    def check_os_utils(self):
        '''
        COMENTAR
        '''
        
        utils = ['nmap','python-tk']
        
        for util in utils:
            if spawn.find_executable(util) is None:
                print('ATENTION! ' + util + 'is not installed on your operating system. You need to install it and then run the application again')
            else:
                print(util + ' is installed')
                
    def check_pip_utils(self):
        '''
        COMENTAR
        '''
        
        pip_utils = ['python-nmap','pysnmp','netifaces','schedule','networkx','matplotlib']
        
        installed_utils = get_pip_installations()
        installed_utils_list = sorted(['%s' % i.key for i in installed_utils])
        
        for util in pip_utils:
            if util not in installed_utils_list:
                toret = ''
                
                while toret not in ['y','n','Y','N']:
                    print(util + ' was not found. Would you like to install this util? (y/n)')
                    answer = raw_input('Answer: ')
                    
                if answer in ['y','Y']:
                    self.__install_util(util)
                else:
                    print(util + 'needs tobe installed to run the application. Execute pip install ' + util + ' and then run the script again.')
            else:
                print('Found ' + util + ' package')
                
    def __install_util(self,util):
        '''
        COMENTAR
        '''
        
        try:
            if hasattr(pip,'main'):
                pip.main(['install',util])
            else:
                pip._internal.main(['install',util])
        except Exception as e:
            print('An error has been occured installing ' + util + '. Pleaser install it manually.')
            
        print(util + 'was installed succesfully. Please run again the application.')
        exit()
        
        
