#Importar librerias
import sys
import schedule
import time

#Importar modulos de terceros
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

    print('What do you want to do?')
    print('')
    print('1) Run the script periodically')
    print('2) Run the script only once')
    print('3) Build a graph from csv file')
    print('')
    op = raw_input('Insert your option: ')
    while op == '' or op not in ['1','2','3']:
        op = raw_input('Enter your option: ')

    if op == '1':
        ipmask_interface = getIpMascByInterface()
        ipmask = ipmask_interface[0]
        interface = ipmask_interface[1]
        
        print("Network IP assign to the chosen interface: " + ipmask)
        print('')

        directory_name = raw_input('Enter the name of the directory where you want to store output files: ')
        while directory_name == '':
            directory_name = raw_input('Enter the name of the directory where you want to store output files: ')
        
        folder_name = periodic_scan_check_folder(directory_name)

        output_files_name = raw_input('Enter the name of output files: ')
        while output_files_name == '':
            output_files_name = raw_input('Enter the name of output files: ')

        interval = raw_input('How often do you want to run the script? (Minutes): ')
        try:
            interval = int(interval)
        except ValueError:
            print "ATENTION! You must to enter an integer."
        while type(interval) != int:
            interval = raw_input('How often do you want to run the script? (Minutes): ')
            interval = int(interval)

        times = raw_input('Enter the number of times that you want to run the script: ')
        try:
            times = int(times)
        except ValueError:
            print "ATENTION! You must to enter an integer."
        while type(times) != int:
            times = raw_input('Enter the number of times that you want to run the script: ')
            times = int(times)

        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_file_name = output_files_name + '_' + current_datetime
        
        #Creates the Scanner with the indicated arguments by the user
        scanner = Scanner(ipmask,interface,folder_name,output_file_name)
        print('')
        print('>>>>>>>>>> Starting periodic scanning <<<<<<<<<<')
        print('')

        scanner.periodic_scan(times)
        schedule.every(interval).minutes.do(scanner.periodic_scan,times)
        
        while True:
            schedule.run_pending()
            time.sleep(1)

    elif op == '2':
        ipmask_interface = getIpMascByInterface()
        ipmask = ipmask_interface[0]
        interface = ipmask_interface[1]
        
        print("Network IP assign to the chosen interface: " + ipmask)
        print('')

        directory_name = raw_input('Insert the name of the directory where you want to store output files: ')
        while directory_name == '':
            directory_name = raw_input('Insert the name of the directory where you want to store output files: ')
        
        folder_name = no_periodic_scan_check_folder(directory_name)

        output_files_name = raw_input('Insert the name of output files: ')
        while output_files_name == '':
            output_files_name = raw_input('Insert the name of output files: ')

        #Creates the Scanner with the indicated arguments by the user
        scanner = Scanner(ipmask,interface,folder_name,output_files_name)
        print('')
        print('>>>>>>>>>> Starting scanning <<<<<<<<<<')
        print('')
        scanner.scan()
    else:
        directory_name = raw_input('Insert the name of the folder where csv file is stored: ')
        while directory_name == '':
            directory_name = raw_input('Insert the name of the folder where csv file is stored: ')

        folder_name = check_if_folder_exists(directory_name)

        file_name = raw_input('Insert the name of the csv file: ')
        while file_name == '':
            file_name = raw_input('Insert the name of the csv file: ')

        #Creates the Scanner with the indicated arguments by the user
        scanner = Scanner('127.0.0.0/8','lo',folder_name,file_name)
        print('')
        print('>>>>>>>>>> Building Network Graph <<<<<<<<<<')
        print('')
        scanner.build_graph_from_csv()

if __name__ == "__main__":
    main()
