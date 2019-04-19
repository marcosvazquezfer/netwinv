#!/usr/bin/python

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

#Definir constantes

#Definir variables globales

nm = nmap.PortScanner()
#current_datetime = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
#outputFile = csv.writer(open('output_' + current_datetime + '.csv', 'wb'))
#outputFile = csv.writer(open('output.csv', 'wb'))
#toret = {}

#Definir clases

#Definir funciones



def banner():
    '''
    COMENTAR
    '''

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
'''
    print('')
    print('                                                                ')
    print('****************************************************************')
    print(' _   _ _____ _____ _   _    _    ____  ____ ___ _   ___     __  ')
    print('| \ | | ____|_   _| | | |  / \  |  _ \|  _ \_ _| \ | \ \   / /  ')
    print('|  \| |  _|   | | | |_| | / _ \ | |_) | | | | ||  \| |\ \ / /   ') 
    print('| |\  | |___  | | |  _  |/ ___ \|  _ <| |_| | || |\  | \ V /    ')  
    print('|_| \_|_____| |_| |_| |_/_/   \_\_| \_\____/___|_| \_|  \_/     ')
    print('                                                                ')
    print('****************************************************************')
    print('')
    print('Python Network and Hardware Inventory Tool')
    print('Made by Marcos Vazquez Fernandez')
    print('')
'''
''' 
    print('')
    print('                                                        ')
    print('********************************************************')
    print(' _   _ _____ _____ _   ___        _____ _   ___     __  ')
    print('| \ | | ____|_   _| | | \ \      / /_ _| \ | \ \   / /  ')
    print('|  \| |  _|   | | | |_| |\ \ /\ / / | ||  \| |\ \ / /   ')
    print('| |\  | |___  | | |  _  | \ V  V /  | || |\  | \ V /    ')
    print('|_| \_|_____| |_| |_| |_|  \_/\_/  |___|_| \_|  \_/     ')
    print('                                                        ')
    print('********************************************************')
    print('')
    print('Python Network and Hardware Inventory Tool')
    print('Made by Marcos Vazquez Fernandez')
    print('')
'''
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
#banner = pyfiglet.figlet_format('NETHWINV')
#print(banner)

#interface = selectInterface()
ipmask_interface = getIpMascByInterface()
ipmask = ipmask_interface[0]
interface = ipmask_interface[1]

print("Dir de red asignada a la interfaz elegida: " + ipmask)
'''
ip = raw_input("Introduzca la IP a escanear: ")

while ip == "":
    ip = raw_input("Introduzca la IP a escanear: ")
'''
print('')

resp = raw_input('Quieres ejecutar el script periodicamente? (s/n) ')
while resp == '':
    resp = raw_input('Quieres ejecutar el script periodicamente? (s/n) ')

folder_name = raw_input('Introduce el nombre del directorio donde quieres almacenar los csv de salida: ')
while folder_name == '':
    folder_name = raw_input('Introduce el nombre del directorio donde quieres almacenar los csv de salida: ')

csv_name = raw_input('Introduce el nombre de salida del fichero csv: ')
while csv_name == '':
    csv_name = raw_input('Introduce el nombre de salida del fichero csv: ')

scanner = Scanner(ipmask,interface,folder_name,csv_name)
    
if resp in ['s','S']:
    print('')
    print('>>>>>>>>>> Empezando escaneo periodico <<<<<<<<<<')
    print('')
    scanner.scan('ping')
    schedule.every(20).minutes.do(scanner.scan,'ping')
    
    while True:
        schedule.run_pending()
        time.sleep(1)
else:
    print('')
    print('>>>>>>>>>> Empezando escaneo <<<<<<<<<<')
    print('')
    scanner.scan('ping')

#scanner = Scanner(ipmask)
#scanner.scan('ping')



#active_ips_scanning = nm.scan(ip, arguments="-sP")
#active_ips_scanning2 = nm.scan(ip, arguments="-T4 -Pn")
#hosts = nm.all_hosts()
#print(len(active_ips_scanning['scan'].keys()))
#print(len(active_ips_scanning2))


'''for host in hosts:
    print("/********************** HOST " + host + " **********************/\n")
    print(">Nombre: " + toret[host]['nombre'])
    print('>MAC: ' + toret[host]['MAC'])
    print(">S.O.: " + toret[host]['SO'])
    print(">Procesador: " + toret[host]['procesador'])
    print(">Tamanho total RAM (GB): " + toret[host]['ram'])
    print(">Tamanho total disco (GB): " + toret[host]['disco'])
    print("\n")'''
    
'''    if snmp_port_scanning['scan'][host] != []:
        if snmp_port_scanning['scan'][host]['udp'] != []:
            if os_scanning['scan'][host]['osmatch'] != []:
                if addresses_keys[0] == 'mac':
                    print("Dir. IP: " + host + ' - Dir MAC: ' + active_ips_scanning['scan'][host]['addresses']['mac'] + " - Estado puerto: " + snmp_port_scanning['scan'][host]['udp'][161]['state'] + " - S.O.: " + os_scanning['scan'][host]['osmatch'][0]['name'])
                else:
                    print("Dir. IP: " + host + " - Estado puerto: " + snmp_port_scanning['scan'][host]['udp'][161]['state'] + " - S.O.: " + os_scanning['scan'][host]['osmatch'][0]['name'])
            else:
                if addresses_keys[0] == 'mac':
                    print("Dir. IP: " + host + ' - Dir MAC: ' + active_ips_scanning['scan'][host]['addresses']['mac'] + " - Estado puerto: " + snmp_port_scanning['scan'][host]['udp'][161]['state'])
                else:
                    print("Dir. IP: " + host + " - Estado puerto: " + snmp_port_scanning['scan'][host]['udp'][161]['state'])
'''

# results = nm.scan(ip, arguments="-sU -p 161,162")
# results2 = nm2.scan(ip, arguments="-O")

# hosts = nm2.all_hosts()

# for host in hosts:

#     so = ""
#     so2 = {}
#     so3 = []
#     ram = {}
#     ram2 = []
#     disco = {}
#     disco2 = []
#     procesador = {}
#     procesador2 = []
#     nombre = {}
#     nombre2 = []

#     if nm[host]['udp'] != []:
#         if nm[host]['udp'][161]['state'] == 'open':
#             so2 = get(host, ['1.3.6.1.2.1.1.1.0'], hlapi.CommunityData('public'))
#             so3 = so2.values()
#             nombre = get(host, ['1.3.6.1.2.1.1.5.0'], hlapi.CommunityData('public'))
#             nombre2 = nombre.values()
#             procesador = get(host, ['1.3.6.1.2.1.25.3.2.1.3.196609'], hlapi.CommunityData('public'))
#             procesador2 = procesador.values()
#             ram = get(host, ['1.3.6.1.4.1.2021.4.5.0'], hlapi.CommunityData('public'))
#             ram2 = ram.values()
#             disco = get(host, ['1.3.6.1.4.1.2021.9.1.6.1'], hlapi.CommunityData('public'))
#             disco2 = disco.values()

#     if nm2[host]['osmatch'] == []:
#         so = 'Unknown'
#     else:
#         so = nm2[host]['osmatch'][0]['name']
    
#     if so3 == []:
#         toret[host] = {'nombre':'Unknown','SO':so,'procesador':'Unknown','ram':'Unknown','disco':'Unknown'}
#     else:
#         so4 = so3[0]
#         so5 = so4.split(" ")
#         soF = so5[0] + " " + so5[2]

#         procesador3 = procesador2[0]
#         procesador4 = procesador3.split(" ")
#         procesadorF = procesador4[1] + " " + procesador4[2]

#         ram_kb = float(ram2[0])
#         ram_gb = ram_kb/(1024*1024)
#         ram_gb = "{0:.3f}".format(ram_gb)

#         disco_kb = float(disco2[0])
#         disco_gb = disco_kb/(1024*1024)
#         disco_gb = "{0:.3f}".format(disco_gb)

#         toret[host] = {'nombre':nombre2[0],'SO':soF,'procesador':procesadorF,'ram':ram_gb,'disco':disco_gb}

# for host in hosts:
#     print("/********************** HOST " + host + " **********************/\n")
#     print(">Nombre: " + toret[host]['nombre'])
#     print(">S.O.: " + toret[host]['SO'])
#     print(">Procesador: " + toret[host]['procesador'])
#     print(">Tamanho total RAM (GB): " + toret[host]['ram'])
#     print(">Tamanho total disco (GB): " + toret[host]['disco'])
#     print("\n")

#     outputFile.writerow([host,toret[host]['nombre'],toret[host]['SO'],toret[host]['procesador'],toret[host]['ram'],toret[host]['disco']])

