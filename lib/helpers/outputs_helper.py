import os

directories = os.listdir('data/')

def check_folder(folder_name):
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

            check_folder(folder_name)
    else:
        os.mkdir('data/' + folder_name)
        return folder_name
