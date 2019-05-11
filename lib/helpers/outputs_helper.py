import os

directories = os.listdir('data/')

def no_periodic_scan_check_folder(folder_name):
    """
    Returns the name of the folder where output files must be stored.

        :param folder_name: The name name of the folder where output files must be stored
        :type folder_name: str
    """

    if folder_name in directories:
        op = raw_input('This folder already exists, do you want to use it? (y/n): ')
        while op == '' or op not in ['y','Y','n','N']:
            op = raw_input('This folder already exists, do you want to use it? (y/n): ')
        print('')

        if op in ['y','Y']:
            return folder_name
        else:
            folder_name = raw_input('Insert the name of the new folder where you want to store output files: ')
            while folder_name == '':
                folder_name = raw_input('Insert the name of the new folder where you want to store output files: ')
            print('')

            return no_periodic_scan_check_folder(folder_name)
    else:
        os.mkdir('data/' + folder_name, 777)
        return folder_name

def periodic_scan_check_folder(folder_name):
    """
    Returns the name of the folder where output files must be stored.

        :param folder_name: The name name of the folder where output files must be stored
        :type folder_name: str
    """

    if folder_name in directories:
        folder_name = raw_input('This folder already exists. Insert the name of the new folder where you want to store output files: ')
        while folder_name == '':
            folder_name = raw_input('This folder already exists. Insert the name of the new folder where you want to store output files: ')
        print('')
        
        return periodic_scan_check_folder(folder_name)
    else:
        os.mkdir('data/' + folder_name)
        return folder_name

def check_if_folder_exists(folder_name):
    """
    COMENTAR
    """

    if folder_name not in directories:
        print('The folder does not exist')
        new_folder_name = raw_input('Please, enter the name of the folder csv file is stored: ')

        return check_if_folder_exists(new_folder_name)
    else:
        return folder_name
