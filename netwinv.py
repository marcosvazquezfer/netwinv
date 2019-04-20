#Importar librerias
import nmap
import csv
import netifaces
import sys
import schedule
import time
#import pyfiglet

#Importar modulos de terceros
from pysnmp import hlapi
from datetime import datetime

#Importar modulos propios
from tests.tester import *
from lib.core.ConfigurationLoader import *
from lib.core.Scanner import *
from lib.helpers.ip_helper import *
from lib.helpers.outputs_helper import *

#Definir constantes

#Definir variables globales

#Definir clases

#Definir funciones

def banner():
    """
    Shows the application banner.
    """

    print('')
    print('                                                     ')
    print('*****************************************************')
    print(' _   _ _____ _____ __        _____ _   ___     __    ')
    print('| \ | | ____|_   _|\ \      / /_ _| \ | \ \   / /    ')
    print('|  \| |  _|   | |   \ \ /\ / / | ||  \| |\ \ / /     ')
    print('| |\  | |___  | |    \ V  V /  | || |\  | \ V /      ')
    print('|_| \_|_____| |_|     \_/\_/  |___|_| \_|  \_/       ')
    print('                                                     ')
    print('*****************************************************')
    print('')
    print('Python Network and Hardware Inventory Tool')
    print('Made by Marcos Vazquez Fernandez')
    print('')

def main():
    """
    Main script function.
    It makes use by the rest of classes and functions existing in the application and contains the 
    main routine which must be executed.
    """

    if not check_root_mode():
        print("You need to run the script like root user")
        sys.exit(1)

    loader = ConfigurationLoader()

    loader.check_os_utils()
    print('All os utils required are installed')

    loader.check_pip_utils()
    print('All pip utils required are installed')

    print('APPLICATION LOADED SUCCESSFULLY')

    banner()
    
    ipmask_interface = getIpMascByInterface()
    ipmask = ipmask_interface[0]
    interface = ipmask_interface[1]
    
    print("Network IP assign to the chosen interface: " + ipmask)
    print('')

    resp = raw_input('Do you want to execute the script periodically? (y/n) ')
    while resp == '' or resp not in ['y','Y','n','N']:
        resp = raw_input('Do you want to execute the script periodically? (y/n) ')
    
    directory_name = raw_input('Insert the name of the directory where you want to store output files: ')
    while directory_name == '':
        directory_name = raw_input('Insert the name of the directory where you want to store output files: ')
    
    folder_name = check_folder(directory_name)

    output_files_name = raw_input('Insert the name of output files: ')
    while output_files_name == '':
        output_files_name = raw_input('Insert the name of output files: ')

    #Creates the Scanner with the indicated arguments by the user
    scanner = Scanner(ipmask,interface,folder_name,output_files_name)
        
    if resp in ['y','Y']:
        print('')
        print('>>>>>>>>>> Starting periodic scanning <<<<<<<<<<')
        print('')

        scanner.scan('ping')
        schedule.every(20).minutes.do(scanner.scan,'ping')
        
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        print('')
        print('>>>>>>>>>> Starting scanning <<<<<<<<<<')
        print('')
        scanner.scan('ping')

if __name__ == "__main__":
    main()
