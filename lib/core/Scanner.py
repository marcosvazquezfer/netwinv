import nmap
import csv
import netifaces
import os


from datetime import datetime
from lib.core.Snmpwalk import *

class Scanner:
    '''
    COMENTAR
    '''
    
    def __init__(self,ip,folder,csv):
        
        self.__nmap = nmap.PortScanner()
        self.__ip = ip
        self.__folder = folder
        self.__csv = csv
        
    @property
    def nmap(self):
        return self.__nmap
    
    @property
    def ip(self):
        return self.__ip

    @property
    def folder(self):
        return self.__folder

    @property
    def csv(self):
        return self.__csv
    
    def __ping_scanning(self):
        '''
        COMENTAR
        '''
        
        active_ips = self.nmap.scan(self.ip,arguments="-sP")
        
        hosts = self.nmap.all_hosts()
        
        return [active_ips,hosts]
    
    def __no_ping_scanning(self):
        '''
        COMENTAR
        '''
        
        active_ips = self.nmap.scan(self.ip,arguments="-T4 -Pn")
        
        hosts = self.nmap.all_hosts()
        
        return [active_ips,hosts]
    
    def __snmp_port_scanning(self,host):
        '''
        COMENTAR
        '''
        
        snmp_scanning = self.nmap.scan(host, arguments="-sU -p 161")
        snmp_scanning_keys = snmp_scanning['scan'].keys()
        
        return[snmp_scanning,snmp_scanning_keys]
    
    def __os_scanning(self,host):
        '''
        COMENTAR
        '''
        
        scanning = self.nmap.scan(host,arguments="-O")
        os_scanning_keys = scanning['scan'].keys()
        
        return [scanning,os_scanning_keys]
    
    def scan(self,type):
        '''
        COMENTAR
        '''
        
        csv_name = self.__output_file_name()
        output_file = csv.writer(open(csv_name,'wb'))
        toret = {}
        
        if type == 'ping':
            ping_scanning = self.__ping_scanning()
            active_ips = ping_scanning[0]
            hosts = ping_scanning[1]
            
            for host in hosts:
                print('Scanning ' + host + '...')
                addresses_keys = active_ips['scan'][host]['addresses'].keys()
                snmp_scanning = self.__snmp_port_scanning(host)
                snmp_port_scanning = snmp_scanning[0]
                snmp_port_scanning_keys = snmp_scanning[1]
                os_scanning = self.__os_scanning(host)
                os_scanning_res = os_scanning[0]
                os_scanning_keys = os_scanning[1]
                
                snmp_information = []
                
                if addresses_keys[0] == 'mac':
                    mac = active_ips['scan'][host]['addresses']['mac']
                else:
                    mac = 'Unknown'
                    
                for key in snmp_port_scanning_keys:
                    if host == key:
                        if snmp_port_scanning['scan'][host] != []:
                            if snmp_port_scanning['scan'][host]['udp'] != []:
                                if snmp_port_scanning['scan'][host]['udp'][161]['state'] == 'open':
                                    snmp = Snmpwalk(['1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.25.3.2.1.3.196609','1.3.6.1.4.1.2021.4.5.0','1.3.6.1.4.1.2021.9.1.6.1'])
                                    try:
                                        snmp_results = snmp.get(host,hlapi.CommunityData('public'))
                                        snmp_information = snmp_results.values()
                                    except RuntimeError:
                                        pass
                                    
                for key in os_scanning_keys:
                    if host == key:
                        if os_scanning_res['scan'][host] != []:
                            if os_scanning_res['scan'][host]['osmatch'] == []:
                                so = 'Unknown'
                            else:
                                so = os_scanning_res['scan'][host]['osmatch'][0]['name']
                        else:
                            so = 'Unknown'
                    else:
                        so = 'Unknown'
                        
                if snmp_information == []:
                    if active_ips['scan'][host]['hostnames'][0]['name'] == '':
                        toret[host] = {'nombre':'Unknown','MAC':mac,'SO':so,'procesador':'Unknown','ram':'Unknown','disco':'Unknown'}
                    else:
                        toret[host] = {'nombre':active_ips['scan'][host]['hostnames'][0]['name'],'MAC':mac,'SO':so,'procesador':'Unknown','ram':'Unknown','disco':'Unknown'}
                else:
                    so = snmp_information[4].split(' ')
                    soF = so[0] + ' ' + so[2]

                    processor = snmp_information[3].split(' ')
                    procesadorF = processor[1] + ' ' + processor[2]
                    
                    ram_kb = float(snmp_information[0])
                    ram_gb = ram_kb/(1024*1024)
                    ram_gb = "{0:.3f}".format(ram_gb)

                    disco_kb = float(snmp_information[2])
                    disco_gb = disco_kb/(1024*1024)
                    disco_gb = "{0:.3f}".format(disco_gb)



                    toret[host] = {'nombre':snmp_information[1],'MAC':mac,'SO':soF,'procesador':procesadorF,'ram':ram_gb,'disco':disco_gb}
                    
                print("/********************** HOST " + host + " **********************/\n")
                print(">Nombre: " + toret[host]['nombre'])
                print('>MAC: ' + toret[host]['MAC'])
                print(">S.O.: " + toret[host]['SO'])
                print(">Procesador: " + toret[host]['procesador'])
                print(">Tamanho total RAM (GB): " + toret[host]['ram'])
                print(">Tamanho total disco (GB): " + toret[host]['disco'])
                print("\n")
                
                output_file.writerow([host,toret[host]['MAC'],toret[host]['nombre'],toret[host]['SO'],toret[host]['procesador'],toret[host]['ram'],toret[host]['disco']])
        else:
            no_ping_scanning = self.__no_ping_scanning()
            active_ips = no_ping_scanning[0]
            hosts = no_ping_scanning[1]
            
            for host in hosts:
                print('Scanning ' + host + '...')
                addresses_keys = active_ips['scan'][host]['addresses'].keys()
                snmp_scanning = self.__snmp_port_scanning(host)
                snmp_port_scanning = snmp_scanning[0]
                snmp_port_scanning_keys = snmp_scanning[1]
                os_scanning = self.__os_scanning(host)
                os_scanning_res = os_scanning[0]
                os_scanning_keys = os_scanning[1]
                
                mac = ''
                so = ""
                so2 = {}
                so3 = []
                ram = {}
                ram2 = []
                disco = {}
                disco2 = []
                procesador = {}
                procesador2 = []
                nombre = {}
                nombre2 = []
                
                if addresses_keys[0] == 'mac':
                    mac = active_ips_scanning['scan'][host]['addresses']['mac']
                else:
                    mac = 'Unknown'
                    
                for key in snmp_port_scanning_keys:
                    if host == key:
                        if snmp_port_scanning['scan'][host] != []:
                            if snmp_port_scanning['scan'][host]['udp'] != []:
                                if snmp_port_scanning['scan'][host]['udp'][161]['state'] == 'open':
                                    so2 = get(host, ['1.3.6.1.2.1.1.1.0'], hlapi.CommunityData('public'))
                                    so3 = so2.values()
                                    nombre = get(host, ['1.3.6.1.2.1.1.5.0'], hlapi.CommunityData('public'))
                                    nombre2 = nombre.values()
                                    procesador = get(host, ['1.3.6.1.2.1.25.3.2.1.3.196609'], hlapi.CommunityData('public'))
                                    procesador2 = procesador.values()
                                    ram = get(host, ['1.3.6.1.4.1.2021.4.5.0'], hlapi.CommunityData('public'))
                                    ram2 = ram.values()
                                    disco = get(host, ['1.3.6.1.4.1.2021.9.1.6.1'], hlapi.CommunityData('public'))
                                    disco2 = disco.values()
                                    
                for key in os_scanning_keys:
                    if host == key:
                        if os_scanning_res['scan'][host] != []:
                            if os_scanning_res['scan'][host]['osmatch'] == []:
                                so = 'Unknown'
                            else:
                                so = os_scanning_res['scan'][host]['osmatch'][0]['name']
                        else:
                            so = 'Unknown'
                    else:
                        so = 'Unknown'
                        
                if so3 == []:
                    toret[host] = {'nombre':active_ips['scan'][host]['hostnames'][0]['name'],'MAC':mac,'SO':so,'procesador':'Unknown','ram':'Unknown','disco':'Unknown'}
                else:
                    so4 = so3[0]
                    so5 = so4.split(" ")
                    soF = so5[0] + " " + so5[2]

                    procesador3 = procesador2[0]
                    procesador4 = procesador3.split(" ")
                    procesadorF = procesador4[1] + " " + procesador4[2]
                    
                    ram_kb = float(ram2[0])
                    ram_gb = ram_kb/(1024*1024)
                    ram_gb = "{0:.3f}".format(ram_gb)

                    disco_kb = float(disco2[0])
                    disco_gb = disco_kb/(1024*1024)
                    disco_gb = "{0:.3f}".format(disco_gb)

                    toret[host] = {'nombre':nombre2[0],'MAC':mac,'SO':soF,'procesador':procesadorF,'ram':ram_gb,'disco':disco_gb}
                    
                print("/********************** HOST " + host + " **********************/\n")
                print(">Nombre: " + toret[host]['nombre'])
                print('>MAC: ' + toret[host]['MAC'])
                print(">S.O.: " + toret[host]['SO'])
                print(">Procesador: " + toret[host]['procesador'])
                print(">Tamanho total RAM (GB): " + toret[host]['ram'])
                print(">Tamanho total disco (GB): " + toret[host]['disco'])
                print("\n")
                
                output_file.writerow([host,toret[host]['MAC'],toret[host]['nombre'],toret[host]['SO'],toret[host]['procesador'],toret[host]['ram'],toret[host]['disco']])
        
        self.__build_mac_ips(toret)
    
    def __build_mac_ips(self,dic):
        
        dic_keys = dic.keys()
        mac_ips = {}
        
        for key in dic_keys:
            if mac_ips == {}:
                mac_ips[dic[key]['MAC']] = [key]
            else:
                mac_ips_keys = mac_ips.keys()

                for mac in mac_ips_keys:
                    if(mac == dic[key]['MAC']):
                        mac_ips[mac].append(key)
                    else:
                        mac_ips[dic[key]['MAC']] = [key]
        
        mac_ips_keys = mac_ips.keys()
        
        for key in mac_ips_keys:
            values = mac_ips[key]
            for i in range(len(values)):
                print('/**** MAC ' + key + ' ****/')
                print('>IP: ' + values[i])
                print('')
    

    
    def __output_file_name(self):
        '''
        COMENTAR
        '''
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        directories = os.listdir('data/')

        if self.folder in directories:
            op = raw_input('La carpeta ya existe, quieres utilizarla? (s/n): ')
            while op == '':
                op = raw_input('La carpeta ya existe, quieres utilizarla? (s/n): ')
            print('')

            if op in ['s','S']:
                return 'data/' + self.folder + '/' + self.csv + '_' + current_datetime + '.csv'
            else:
                self.folder = raw_input('Introduce el nombre del nuevo directorio donde quieres almacenar los csv de salida: ')
                while self.folder == '':
                    self.folder = raw_input('Introduce el nombre del nuevo directorio donde quieres almacenar los csv de salida: ')
                print('')

                os.mkdir('data/' + self.folder)
                return 'data/' + self.folder + '/' + self.csv + '_' + current_datetime + '.csv'
        else:
            os.mkdir('data/' + self.folder)
            return 'data/' + self.folder + '/' + self.csv + '_' + current_datetime + '.csv'
        
            
        
