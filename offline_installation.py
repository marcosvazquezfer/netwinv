import os
import sys
import subprocess as s

from lib.helpers.colors import *


def permissions_error(err):
    """ Checks if an error is caused by lack of user permissions.

        :param err: Error to check
        :type err: tuple
        :return: True if the error is about permissions.
        :return: False if the error is not about permissions
        :rtype: bool
    """

    if ('permitted' in err or 'permissions' in err) and 'DEPRECATION' not in err:
        return True
    return False


def install_nmap():
    """ Linux system based nmap installation, for Red Hat and Debian distributions.

    As the nmap package is a .rpm file, Debian distributions need alien to install it.
    Suppose that the system is a Red Hat system at first, if not, install
    alien and then the .rpm file with it.
    """

    pkt_dir = './packages/os'
    alien_file = None
    nmap_file = None

    # Check for nmap file
    try:
        nmap_file = [f for f in os.listdir(pkt_dir) if 'nmap' in f][0]
    except IndexError:
        halt_fail('Nmap(.rpm) package not found under ./packages/os')

    # Execute RPM file installation with yum, Red Hat distribution
    nmap_install = s.Popen(['yum', 'install', pkt_dir + '/' + nmap_file], stderr=s.PIPE)
    errors = nmap_install.communicate()
    # If errors, it probably means it is a Debian based SO
    if len(errors):
        if permissions_error(errors):
            halt_fail('Popped error about permissions, try executing "sudo python offline_install.py"')
        print_fail('Could not install nmap with yum:\n{}'.format(errors))

        # Ask user if he wants to try installation with alien. Keep asking until a valid answer
        option = 'k'
        while option.lower() not in ['y', 'n']:
            option = raw_input('Do you want to attempt nmap installation with alien? If your system is Red Hat based,'
                               ' please re-read the STDERR from above before answering [Y/n]: ')

        # If user says yes
        if 'y' in option.lower():
            print_warning('Attempting alien installation.')

            # Check for alien file
            try:
                alien_file = [f for f in os.listdir(pkt_dir) if 'alien' in f][0]
            except IndexError:
                halt_fail('Alien(.deb) package not found under ./packages/os')

            # Install alien
            alien_install = s.Popen(['dpkg', '-i', pkt_dir + '/' + alien_file], stderr=s.PIPE)
            errors = alien_install.communicate()
            # If errors installing alien, halt execution
            if len(errors):
                if permissions_error(errors):
                    halt_fail('Popped error about permissions, try executing "sudo python offline_install.py"')
                halt_fail('Could not install alien, and therefore nmap. STDERR says:\n{}'.format(errors))
            print_success('Successfully installed alien')

            # Install nmap with alien
            nmap_install = s.Popen(['alien', '-i', pkt_dir + '/' + nmap_file], stderr=s.PIPE)
            errors = nmap_install.communicate()
            # If errors intalling nmap with alien, halt execution
            if len(errors):
                if permissions_error(errors):
                    halt_fail('Popped error about permissions, try executing "sudo python offline_install.py"')
                halt_fail('Could not install nmap with alien. STDERR says:\n{}'.format(errors))

        # If user answers no
        else:
            halt_fail('PSCAD cannot be used without nmap. Halting installation...')

    print_success('Successfully installed nmap')


def install_module(pkg):
    """ Installs a given package using the pip command.

        :param pkg: Package to install
        :type pkg: str
    """

    with open('/dev/null') as null_file:
        mod_install = s.Popen(['pip', 'install', 'packages/' + pkg], stderr=s.PIPE, stdout=null_file)
    _, errors = mod_install.communicate()
    # If errors when installing module
    if len(errors):
        if permissions_error(errors):
            halt_fail('Popped error about permissions, try executing "sudo python offline_install.py"')
        if 'DEPRECATION' not in errors:
            halt_fail('Could not install module from {}. STDERR says:\n{}'.format(pkg, errors))

    print_success('Successfully installed module from {}'.format(pkg))


def main():
    """ Checks if pip is on the system, if so, install the dependencies, if not, execute the get-pip.py script
    to install it
    """

    has_pip = False
    pkg_dir = './packages'

    try:
        with open('/dev/null', 'w') as null_file:
            s.check_call(['nmap',  '-h'], stdout=null_file)
        print_success('Nmap found on the system.')
    except s.CalledProcessError:
        print_fail('Nmap not found on the system, attempting installation...')
        install_nmap()

    # Check if pip is installed
    try:
        with open('/dev/null', 'w') as null_file:
            s.check_call(['pip', '-h'], stdout=null_file)
        has_pip = True
        print_success('pip found on the system.')
    except s.CalledProcessError:
        print_fail('pip is not installed in the system. Executing get-pip.py...')

    # If pip needs to be installed
    if not has_pip:
        # Execute the get-pip.py script
        pip_installation = s.Popen(['python', 'packages/get-pip.py'], stderr=s.PIPE)
        # Store errors
        errors = pip_installation.communicate()
        # If errors, show them and halt execution
        if len(errors):
            print_fail('FATAL: Could not install pip. STDERR says:\n{}'.format(errors))
            sys.exit(-1)

        print_success('pip successfully installed.')

    # Get all packages under the ./packages directory. All files under './packages' that are not python executable
    # Do not search recursively
    packages = [f for f in os.listdir(pkg_dir) if os.path.isfile(os.path.join(pkg_dir, f)) and
                '.py' not in f]

    # Install all packages
    for pkg in packages:
        install_module(pkg)

    print_success('All packages have been successfully installed.')


if __name__ == '__main__':
    main()