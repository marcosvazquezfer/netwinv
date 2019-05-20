import os
import sys
import subprocess as s


def check_permissions_error(check_errors):
    """ 
    This function checks if an error is caused by user permissions

        :param check_errors: Error to check
        :type check_errors: tuple
        :return: If the error is about permissions return True.
        :return: If the error is not caused about permissions return False
        :rtype: bool
    """

    if ('permitted' in check_errors or 'permissions' in check_errors) and 'DEPRECATION' not in check_errors:
        return True

    return False


def nmap_installation():
    """ 
    Nmap offline installation for distributions based on Debian and Red Hat.

    If the nmap package is a .rpm file, Debian distributions need alien to install it.
    Suppose that the system is a Red Hat system at first, if not, install alien and then the .rpm file with it.
    """

    directory_os_packages = './packages/os'
    alien_file = None
    nmap_file = None

    # Search nmap file
    try:
        nmap_file = [f for f in os.listdir(directory_os_packages) if 'nmap' in f][0]
    except IndexError:
        print('ATENTION: nmap package is not in the /package/os folder')

    # For distributions based on Red Hat, execute installation with yum
    nmap_install = s.Popen(['yum', 'install', directory_os_packages + '/' + nmap_file], stderr=s.PIPE)
    errors = nmap_install.communicate()

    # If exists any errors, it probably means that it is a distribution based on Debian
    if len(errors) > 0:
        if check_permissions_error(errors) == True:
            print('ATENTION: Found an error of permissions. Execute "sudo python offline_install.py"')
        print('ATENTION: It is not possible to use yum to install nmap:\n{}'.format(errors))

        # Ask user if he wants to try installation with alien
        option = 'k'
        while option.lower() not in ['y', 'n']:
            option = raw_input('Do you want to try nmap installation with alien? If you have an O.S. based on Red Hat, read the previous error (Y/n): ')

        if 'y' in option.lower():
            print('Trying alien installation...')

            # Search alien file
            try:
                alien_file = [f for f in os.listdir(directory_os_packages) if 'alien' in f][0]
            except IndexError:
                print('ATENTION: alien package was not found in the /packages/os folder')

            # Install alien
            alien_install = s.Popen(['dpkg', '-i', directory_os_packages + '/' + alien_file], stderr=s.PIPE)
            errors = alien_install.communicate()

            # Stops the execution if exists errors installing alien
            if len(errors) > 0:
                if check_permissions_error(errors) == True:
                    print('ATENTION: Found an error of permissions. Execute "sudo python offline_install.py"')
                print('ATENTION: It is not possible to install alien and then nmap either:\n{}'.format(errors))
            print_success('Alien was succesfully installed')

            # Install nmap with alien
            nmap_install = s.Popen(['alien', '-i', directory_os_packages + '/' + nmap_file], stderr=s.PIPE)
            errors = nmap_install.communicate()

            # Stops the exectuion if exists errors installing nmap with alien
            if len(errors) > 0:
                if check_permissions_error(errors) == True:
                    print('ATENTION: Found an error of permissions. Execute "sudo python offline_install.py"')
                print('ATENTION: It is not possible to use alien to install nmap:\n{}'.format(errors))

        else:
            print('ATENTION: NetwInv could not use without nmap')

    print('Nmap installation was succesfully')


def install_module(package):
    """ 
    This function is used to install a package using pip command.

        :param package: The package to install
        :type package: str
    """

    with open('/dev/null') as null_file:
        mod_install = s.Popen(['pip', 'install', 'packages/' + package], stderr=s.PIPE, stdout=null_file)
    _, errors = mod_install.communicate()

    # If exists any errors installing package
    if len(errors) > 0:
        if check_permissions_error(errors) == True:
            print('ATENTION: Found an error of permissions. Execute "sudo python offline_install.py"')

        if 'DEPRECATION' not in errors:
            print('ATENTION: It is not possible to install module from {}. STDERR says:\n{}'.format(package, errors))

    print('Module was succesfully installed')


def main():
    """ 
    Search pip on the system, if exists install dependencies. 
    If not exists execute get-pip.py script to install it.
    """

    pip_exist = False
    package_folder = './packages'

    try:
        with open('/dev/null', 'w') as null_file:
            s.check_call(['nmap',  '-h'], stdout=null_file)
        print('Nmap was found on the system.')
    except s.CalledProcessError:
        print('ATENTION: Nmap was not found on the system, trying to install.')
        nmap_installation()

    # Search pip
    try:
        with open('/dev/null', 'w') as null_file:
            s.check_call(['pip', '-h'], stdout=null_file)
        pip_exist = True
        print('pip was found on the system.')
    except s.CalledProcessError:
        print('ATENTION: pip was not found on the system. Executing get-pip.py.')

    # It is neccesary to install pip
    if not pip_exist:
        # Execute the get-pip.py script
        pip_installation = s.Popen(['python', 'packages/get-pip.py'], stderr=s.PIPE)
        errors = pip_installation.communicate()

        # If exists any errors, show them and stops execution
        if len(errors) > 0:
            print('ATENTION: Could not install pip. STDERR says:\n{}'.format(errors))
            sys.exit(-1)

        print('pip successfully installed.')

    packages = [f for f in os.listdir(package_folder) if os.path.isfile(os.path.join(package_folder, f)) and
                '.py' not in f]

    # Install packages
    for package in packages:
        install_module(package)

    print('All the neccesary packages were installed correctly')

if __name__ == '__main__':
    main()