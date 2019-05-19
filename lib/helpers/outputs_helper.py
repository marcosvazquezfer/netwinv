import os

directories = os.listdir('data/')

def no_periodic_scan_check_folder(folder_name):
    """
    Returns the name of the folder where output files must be stored in simple scan.

        :param folder_name: The name name of the folder where output files must be stored
        :type folder_name: str
    """

    # If folder exists asks if the user wants to use it. If not, create the folder and return it
    if folder_name in directories:
        op = raw_input('This folder already exists, do you want to use it? (y/n): ')
        while op == '' or op not in ['y','Y','n','N']:
            op = raw_input('This folder already exists, do you want to use it? (y/n): ')

        # If the answer is yes, returns the folder name. If the answer is no, a new one must be introduced
        if op in ['y','Y']:
            return folder_name
        else:
            print('')
            folder_name = raw_input('Insert the name of the new folder where you want to store output files: ')
            while folder_name == '':
                folder_name = raw_input('Insert the name of the new folder where you want to store output files: ')

            # Callback to check if the new introduced folder exists
            return no_periodic_scan_check_folder(folder_name)
    else:
        os.mkdir('data/' + folder_name, 777)
        return folder_name

def periodic_scan_check_folder(folder_name):
    """
    Returns the name of the folder where output files must be stored in periodic scan.

        :param folder_name: The name name of the folder where output files must be stored
        :type folder_name: str
    """

    # If folder exists, print an error message and a new one must be introduced. 
    # If not, create the folder and return it
    if folder_name in directories:
        print('ATENTION: This folder already exists!')
        folder_name = raw_input('Insert the name of the new folder where you want to store output files: ')
        while folder_name == '':
            print('ATENTION: This folder already exists!')
            folder_name = raw_input('Insert the name of the new folder where you want to store output files: ')
        
        # Callback to check if the folder exists
        return periodic_scan_check_folder(folder_name)
    else:
        os.mkdir('data/' + folder_name)
        return folder_name

def check_if_folder_exists(folder_name):
    """
    Check if the folder that is passed as a parameter exists

        :param folder_name: The name of the folder where csv file must be stored
        :param type: str
    """

    # If folder does not exists, print an error message and a new one must be introduced
    if folder_name not in directories:
        print('ATENTION: The folder does not exist!')
        new_folder_name = raw_input('Please, enter the name of the folder csv file is stored: ')

        # Callback to check if the new introduced folder exists
        return check_if_folder_exists(new_folder_name)
    else:
        # Return the folder
        return folder_name
