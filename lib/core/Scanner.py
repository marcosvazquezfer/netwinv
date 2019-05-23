import nmap
import csv
import os.path
import sys
import networkx as nx
import matplotlib.pyplot as plt

from datetime import datetime

from lib.core.Snmpwalk import *
from lib.core.PDFWriter import *
from lib.helpers.ip_helper import *
from lib.helpers.csv_helper import *

class Scanner:
    """
    This class is an implementation of a nmap scanner and file exporter.

    It is the responsible for executing a scan in the indicated network trying to identify alive IPs, 
    MAC network, operating system, name associated with the IP, processor, total size of RAM and
    total size of disk.
    
    When the scan finishes, the class creates a csv output file, a png image which tries to represent
    the network and a pdf file, exporting them to the indicated output directory.

        :param ip: The IP of the network that must be scanned.
        :param interface: The network interface associated with the IP.
        :param folder_name: The name of the directory where output files must be stored.
        :param file_name: The name of the output files.
        :type ip: str
        :type interface: str
        :type folder_name: str
        :type file_name: str
    """
    
    def __init__(self,ip,interface,folder_name,file_name):
        
        self.__nmap = nmap.PortScanner()
        self.__ip = ip
        self.__interface = interface
        self.__folder_name = folder_name
        self.__file_name = file_name
        self.__start_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.__cont_times = 0
        
    @property
    def nmap(self):
        return self.__nmap
    
    @property
    def ip(self):
        return self.__ip
    
    @property
    def interface(self):
        return self.__interface

    @property
    def folder_name(self):
        return self.__folder_name

    @property
    def file_name(self):
        return self.__file_name

    @property
    def start_time(self):
        return self.__start_time
    
    @property
    def cont_times(self):
        return self.__cont_times
    
    def __ping_scanning(self):
        """
        Return a list containing the information extracted with nmap of each active IPs and 
        a list with active IPs.

        It perfoms a scan with ping.
        
        :return: list containing scan information and active IPs
        :rtype: list
        """
        
        # Executes the ping scanning and gets the information
        active_ips = self.nmap.scan(self.ip,arguments="-sP")
        
        # Get all the active IPs
        hosts = self.nmap.all_hosts()
        
        # Return the information and the active IPs
        return [active_ips,hosts]
    
    def __snmp_port_scanning(self,host):
        """
        Returns a list containing the snmp information extracted with nmap of the port UDP 161 associated 
        to the indicated IP and a list with the snmp scanning keys.

            :param host: The IP to scanning port UDP 161.
            :type host: str
            :return: list containing snmp information and snmp scanning keys
            :rtype: list
        """
        
        # Execute snmp port scanning and get the information
        snmp_scanning = self.nmap.scan(host, arguments="-sU -p 161")
        # Get snmp scanning keys
        snmp_scanning_keys = snmp_scanning['scan'].keys()
        
        # Return the information and the keys
        return[snmp_scanning,snmp_scanning_keys]
    
    def __os_scanning(self,host):
        """
        Returns a list containing the operating system information extracted with nmap of the indicated IP 
        and a list with the operating system scanning keys.

            :param host: The IP to perfom operating system scanning.
            :type host: str
            :return: list containing operating system information and operating system scanning keys
            :rtype: list
        """
        
        # Execute os scanning and gets the information
        scanning = self.nmap.scan(host,arguments="-O")
        # Get os  scanning keys
        os_scanning_keys = scanning['scan'].keys()
        
        # Return the information and the keys
        return [scanning,os_scanning_keys]
    
    def scan(self):
        """
        Perfom the scan of the indicated network doing all needed scans. When the scan finishes, a csv file,
        a network graph and a pdf file are created. All the obtain information will be printed in the terminal.
        """

        # Get the time when the scan starts
        self.start_time = datetime.now()
        # Diccionary where the information will be stored
        toret = {}
        # Get the route where csv file must be stored
        csv_name = self.__output_csv_name()
        # csv file is open in write mode
        output = open(csv_name,'wb')
        output_file = csv.writer(output)

        # Ping scanning is done and its information is recovered
        ping_scanning = self.__ping_scanning()
        active_ips = ping_scanning[0]
        hosts = ping_scanning[1]
        
        for host in hosts:
            print('Scanning ' + host + '...')

            # Get all network addresses
            addresses_keys = active_ips['scan'][host]['addresses'].keys()

            # Snmp port scanning is done and its information is recovered
            snmp_scanning = self.__snmp_port_scanning(host)
            snmp_port_scanning = snmp_scanning[0]
            snmp_port_scanning_keys = snmp_scanning[1]
            # OS scanning is done and its information is recovered
            os_scanning = self.__os_scanning(host)
            os_scanning_res = os_scanning[0]
            os_scanning_keys = os_scanning[1]
            
            # Creates a list to store snmp information
            snmp_information = []
            
            # If the current IP has mac address store it. If not, store: Unknown
            if addresses_keys[0] == 'mac':
                mac = active_ips['scan'][host]['addresses']['mac']
            else:
                mac = 'Unknown'
            
            # For each key checks if it is possible to obtain harware infomation.
            # If it is possible, gets the harware information
            for key in snmp_port_scanning_keys:
                if host == key and snmp_port_scanning['scan'][host] != [] and snmp_port_scanning['scan'][host]['udp'] != [] and snmp_port_scanning['scan'][host]['udp'][161]['state'] == 'open':
                    snmp = Snmpwalk(['1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.25.3.2.1.3.196609','1.3.6.1.4.1.2021.4.5.0','1.3.6.1.4.1.2021.9.1.6.1'])
                    try:
                        snmp_results = snmp.get(host,hlapi.CommunityData('public'))
                        snmp_information = snmp_results.values()
                        
                    except RuntimeError:
                        pass
            
            # For each key checks if it is possible to obtain O.S.
            # If it is possible gets it. If not, store: Unknown
            for key in os_scanning_keys:
                if host == key and os_scanning_res['scan'][host] != [] and not os_scanning_res['scan'][host]['osmatch'] == []:
                    so = os_scanning_res['scan'][host]['osmatch'][0]['name']
                else:
                    so = 'Unknown'
            
            # If it does not exists snmp information, for each harware information store: Unknown. 
            # Except O.S that stored the one obtained by os scanning.
            # If exists, gets the O.S. and proccesor, and calculates ram size and disk size in GB.
            if snmp_information == []:
                if active_ips['scan'][host]['hostnames'][0]['name'] == '':
                    toret[host] = {'name':'Unknown','MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
                else:
                    toret[host] = {'name':active_ips['scan'][host]['hostnames'][0]['name'],'MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
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

                toret[host] = {'name':snmp_information[1],'MAC':mac,'OS':soF,'processor':procesadorF,'ram':ram_gb,'disk':disco_gb}
                
            print("/********************** IP " + host + " **********************/\n")
            print(">Nombre: " + toret[host]['name'])
            print('>MAC: ' + toret[host]['MAC'])
            print(">S.O.: " + toret[host]['OS'])
            print(">Procesador: " + toret[host]['processor'])
            print(">Tamanho total RAM (GB): " + toret[host]['ram'])
            print(">Tamanho total disco (GB): " + toret[host]['disk'])
            print("\n")
            
            # Writes a new row in csv output file with the information of the IP scanned
            output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])

        # Close csv file
        output.close()
        print('========> CSV file built and closed')
        print('')

        # Gets csv information
        info = read_csv(csv_name)
        # Groups IPs by its MAC direction
        mac_ips = self.__build_mac_ips(info)

        # Build network graph
        self.__build_graph(mac_ips)
        print('')
        print('========> Network graph created correctly')
        print('')
        # Builds pdf output file
        writer = PDFWriter(lang='esp',output_directory=self.folder_name)
        mac_ips_keys = mac_ips.keys()

        for mac in mac_ips_keys:
            ip_keys = mac_ips[mac]['IP'].keys()
            writer.append_info(
                {'Direccion MAC':mac},
                [[ip,info[ip]['name'],so,info[ip]['processor'],info[ip]['ram'],info[ip]['disk']] for ip in ip_keys for so in mac_ips[mac]['IP'][ip]],
                ['IP','Nombre','Sistema Operativo','Procesador','Memoria RAM (GB)','Espacio alamacenamiento disco (GB)'],
                [3, 2.5, 4, 3, 4, 4]
            )
        writer.write_document()

        print('========> PDF file created correctly')
        print('')

        # Takes the time when the scan began and the time when it finished. Then calculate the days, 
        # hours, minutes and seconds that the scan lasted.
        start = self.start_time
        finish = datetime.now()
        start_datetime = datetime(start.year, start.month, start.day, start.hour, start.minute, start.second)
        finish_datetime = datetime(finish.year, finish.month, finish.day, finish.hour, finish.minute, finish.second)
        required_time = finish_datetime - start_datetime
        seconds = required_time.seconds
        minutes = (seconds // 60) % 60
        hours = seconds // 3600

        print('')
        print('------------> Scan has finished <------------')
        print('')
        print('*************** SCAN RESULTS ****************')
        print('')
        print('Required time: ' + str(required_time.days) + ' days ' + str(hours) + ' hours ' + str(minutes) + ' minutes')
        print('Alive IPs: ' + str(len(toret.keys())))
        print('')
        print('*********************************************')

    def periodic_scan(self,times):
        """
        Perfom the periodic scan of the indicated network, the indicated number of times,
        doing all needed scans. When the scan finishes, a csv file and a network graph are created. 
        All the obtain information will be printed in the terminal.

            :param times: The number of times that scan will be executed
            :type scan_type: int
        """

        # Diccionary where the information will be stored
        toret = {}
        # The route of the csv file
        csv_name = 'data/' + self.folder_name + '/' + self.file_name + '.csv'
        
        # If the number of times that scan should be executed have not been yet reached
        if self.cont_times < times:
            # If csv file exists
            if os.path.isfile(csv_name):
                # csv file information is recovered
                csv_info = read_csv(csv_name)
                csv_info_keys = csv_info.keys()

                # csv file is open in write mode but adding new information at the end of the file
                output = open(csv_name,'a')
                output_file = csv.writer(output)

                # Ping scanning is done and its information is recovered
                ping_scanning = self.__ping_scanning()
                active_ips = ping_scanning[0]
                hosts = ping_scanning[1]
                
                for host in hosts:
                    print('Scanning ' + host + '...')

                    # Gets all network addresses
                    addresses_keys = active_ips['scan'][host]['addresses'].keys()

                    # OS scanning is done and its information is recovered
                    os_scanning = self.__os_scanning(host)
                    os_scanning_res = os_scanning[0]
                    os_scanning_keys = os_scanning[1]
                    
                    # If the current IP has mac address store it. If not, store: Unknown
                    if addresses_keys[0] == 'mac':
                        mac = active_ips['scan'][host]['addresses']['mac']
                    else:
                        mac = 'Unknown'

                    # For each key checks if it is possible to obtain O.S.
                    # If it is possible gets it. If not, store: Unknown
                    for key in os_scanning_keys:
                        if host == key and os_scanning_res['scan'][host] != [] and not os_scanning_res['scan'][host]['osmatch'] == []:
                                so = os_scanning_res['scan'][host]['osmatch'][0]['name']
                        else:
                            so = 'Unknown'

                    # If the IP is in csv file with the same MAC but different O.S. gets its snmp information.
                    #if host in csv_info_keys and csv_info[host]['MAC'] == mac and csv_info[host]['OS'] != so:
                    if host in csv_info_keys and mac in csv_info[host]['MAC'] and so not in csv_info[host]['OS']:
                        snmp_information = []
                        # Snmp port scanning is done and its information recovered
                        snmp_scanning = self.__snmp_port_scanning(host)
                        snmp_port_scanning = snmp_scanning[0]
                        snmp_port_scanning_keys = snmp_scanning[1]

                        # For each key checks if it is possible to obtain harware infomation.
                        # If it is possible, gets the harware information
                        for key in snmp_port_scanning_keys:
                            if host == key and snmp_port_scanning['scan'][host] != [] and snmp_port_scanning['scan'][host]['udp'] != [] and snmp_port_scanning['scan'][host]['udp'][161]['state'] == 'open':
                                snmp = Snmpwalk(['1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.25.3.2.1.3.196609','1.3.6.1.4.1.2021.4.5.0','1.3.6.1.4.1.2021.9.1.6.1'])
                                try:
                                    snmp_results = snmp.get(host,hlapi.CommunityData('public'))
                                    snmp_information = snmp_results.values()
                                except RuntimeError:
                                    pass
                        
                        # If it does not exists snmp information, for each harware information store: Unknown. 
                        # Except O.S that stored the one obtained by os scanning.
                        # If exists, gets the O.S. and proccesor, and calculates ram size and disk size in GB.
                        if snmp_information == []:
                            if active_ips['scan'][host]['hostnames'][0]['name'] == '':
                                toret[host] = {'name':'Unknown','MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
                            else:
                                toret[host] = {'name':active_ips['scan'][host]['hostnames'][0]['name'],'MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
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

                            toret[host] = {'name':snmp_information[1],'MAC':mac,'OS':soF,'processor':procesadorF,'ram':ram_gb,'disk':disco_gb}
                        
                        print("/********************** IP " + host + " **********************/\n")
                        print(">Nombre: " + toret[host]['name'])
                        print('>MAC: ' + toret[host]['MAC'])
                        print(">S.O.: " + toret[host]['OS'])
                        print(">Procesador: " + toret[host]['processor'])
                        print(">Tamanho total RAM (GB): " + toret[host]['ram'])
                        print(">Tamanho total disco (GB): " + toret[host]['disk'])
                        print("\n")
                        
                        # Writes a new row into csv file with the information of the IP scanned
                        output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])
                    
                    # If the IP exists in the csv file but with different MAC, gets its snmp information
                    #elif host in csv_info_keys and csv_info[host]['MAC'] != mac:
                    elif host in csv_info_keys and mac not in csv_info[host]['MAC']:
                        snmp_information = []
                        # Snmp port scanning is done and its information recovered
                        snmp_scanning = self.__snmp_port_scanning(host)
                        snmp_port_scanning = snmp_scanning[0]
                        snmp_port_scanning_keys = snmp_scanning[1]

                        # For each key checks if it is possible to obtain harware infomation.
                        # If it is possible, gets the harware information
                        for key in snmp_port_scanning_keys:
                            if host == key and snmp_port_scanning['scan'][host] != [] and snmp_port_scanning['scan'][host]['udp'] != [] and snmp_port_scanning['scan'][host]['udp'][161]['state'] == 'open':
                                snmp = Snmpwalk(['1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.25.3.2.1.3.196609','1.3.6.1.4.1.2021.4.5.0','1.3.6.1.4.1.2021.9.1.6.1'])
                                try:
                                    snmp_results = snmp.get(host,hlapi.CommunityData('public'))
                                    snmp_information = snmp_results.values()
                                except RuntimeError:
                                    pass
                        
                        # If it does not exists snmp information, for each harware information store: Unknown. 
                        # Except O.S that stored the one obtained by os scanning.
                        # If exists, gets the O.S. and proccesor, and calculates ram size and disk size in GB.
                        if snmp_information == []:
                            if active_ips['scan'][host]['hostnames'][0]['name'] == '':
                                toret[host] = {'name':'Unknown','MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
                            else:
                                toret[host] = {'name':active_ips['scan'][host]['hostnames'][0]['name'],'MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
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

                            toret[host] = {'name':snmp_information[1],'MAC':mac,'OS':soF,'processor':procesadorF,'ram':ram_gb,'disk':disco_gb}
                        
                        print("/********************** IP " + host + " **********************/\n")
                        print(">Nombre: " + toret[host]['name'])
                        print('>MAC: ' + toret[host]['MAC'])
                        print(">S.O.: " + toret[host]['OS'])
                        print(">Procesador: " + toret[host]['processor'])
                        print(">Tamanho total RAM (GB): " + toret[host]['ram'])
                        print(">Tamanho total disco (GB): " + toret[host]['disk'])
                        print("\n")
                        
                        # Writes a new row into csv file with the information of the IP scanned
                        output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])

                    # If IP does not exist in the csv file, gets all its information
                    elif host not in csv_info_keys:
                        snmp_information = []

                        # Snmp port scanning is done and its information recovered
                        snmp_scanning = self.__snmp_port_scanning(host)
                        snmp_port_scanning = snmp_scanning[0]
                        snmp_port_scanning_keys = snmp_scanning[1]

                        # For each key checks if it is possible to obtain harware infomation.
                        # If it is possible, gets the harware information
                        for key in snmp_port_scanning_keys:
                            if host == key and snmp_port_scanning['scan'][host] != [] and snmp_port_scanning['scan'][host]['udp'] != [] and snmp_port_scanning['scan'][host]['udp'][161]['state'] == 'open':
                                snmp = Snmpwalk(['1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.25.3.2.1.3.196609','1.3.6.1.4.1.2021.4.5.0','1.3.6.1.4.1.2021.9.1.6.1'])
                                try:
                                    snmp_results = snmp.get(host,hlapi.CommunityData('public'))
                                    snmp_information = snmp_results.values()
                                except RuntimeError:
                                    pass
                        # If it does not exists snmp information, for each harware information store: Unknown. 
                        # Except O.S that stored the one obtained by os scanning.
                        # If exists, gets the O.S. and proccesor, and calculates ram size and disk size in GB.
                        if snmp_information == []:
                            if active_ips['scan'][host]['hostnames'][0]['name'] == '':
                                toret[host] = {'name':'Unknown','MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
                            else:
                                toret[host] = {'name':active_ips['scan'][host]['hostnames'][0]['name'],'MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
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

                            toret[host] = {'name':snmp_information[1],'MAC':mac,'OS':soF,'processor':procesadorF,'ram':ram_gb,'disk':disco_gb}

                        print("/********************** HOST " + host + " **********************/\n")
                        print(">Nombre: " + toret[host]['name'])
                        print('>MAC: ' + toret[host]['MAC'])
                        print(">S.O.: " + toret[host]['OS'])
                        print(">Procesador: " + toret[host]['processor'])
                        print(">Tamanho total RAM (GB): " + toret[host]['ram'])
                        print(">Tamanho total disco (GB): " + toret[host]['disk'])
                        print("\n")
                        
                        # Writes a new row into csv file with the information of the scanned IP
                        output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])

                # Close the csv file
                output.close()

                print('')

            # If csv file does not exist    
            else:
                # Gets the route of the csv file
                csv_name = 'data/' + self.folder_name + '/' + self.file_name + '.csv'
                # Store the time when the scan start
                self.start_time = datetime.now()
                
                # Open the csv file in write mode
                output = open(csv_name,'wb')
                output_file = csv.writer(output)

                # Ping scanning is done and its information is recovered
                ping_scanning = self.__ping_scanning()
                active_ips = ping_scanning[0]
                hosts = ping_scanning[1]
                
                for host in hosts:
                    print('Scanning ' + host + '...')

                    # Gets all network addresses
                    addresses_keys = active_ips['scan'][host]['addresses'].keys()

                    # Snmp port scanning is done and its information recovered
                    snmp_scanning = self.__snmp_port_scanning(host)
                    snmp_port_scanning = snmp_scanning[0]
                    snmp_port_scanning_keys = snmp_scanning[1]

                    # OS scanning is done and its information is recovered
                    os_scanning = self.__os_scanning(host)
                    os_scanning_res = os_scanning[0]
                    os_scanning_keys = os_scanning[1]
                    
                    snmp_information = []
                    
                    # If the current IP has mac address store it. If not, store: Unknown
                    if addresses_keys[0] == 'mac':
                        mac = active_ips['scan'][host]['addresses']['mac']
                    else:
                        mac = 'Unknown'
                    
                    # For each key checks if it is possible to obtain harware infomation.
                    # If it is possible, gets the harware information
                    for key in snmp_port_scanning_keys:
                        if host == key and snmp_port_scanning['scan'][host] != [] and snmp_port_scanning['scan'][host]['udp'] != [] and snmp_port_scanning['scan'][host]['udp'][161]['state'] == 'open':
                            snmp = Snmpwalk(['1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.25.3.2.1.3.196609','1.3.6.1.4.1.2021.4.5.0','1.3.6.1.4.1.2021.9.1.6.1'])
                            try:
                                snmp_results = snmp.get(host,hlapi.CommunityData('public'))
                                snmp_information = snmp_results.values()
                            except RuntimeError:
                                pass

                    # For each key checks if it is possible to obtain O.S.
                    # If it is possible gets it. If not, store: Unknown                
                    for key in os_scanning_keys:
                        if host == key and os_scanning_res['scan'][host] != [] and not os_scanning_res['scan'][host]['osmatch'] == []:
                            so = os_scanning_res['scan'][host]['osmatch'][0]['name']
                        else:
                            so = 'Unknown'
                    
                    # If it does not exists snmp information, for each harware information store: Unknown. 
                    # Except O.S that stored the one obtained by os scanning.
                    # If exists, gets the O.S. and proccesor, and calculates ram size and disk size in GB.
                    if snmp_information == []:
                        if active_ips['scan'][host]['hostnames'][0]['name'] == '':
                            toret[host] = {'name':'Unknown','MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
                        else:
                            toret[host] = {'name':active_ips['scan'][host]['hostnames'][0]['name'],'MAC':mac,'OS':so,'processor':'Unknown','ram':'Unknown','disk':'Unknown'}
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

                        toret[host] = {'name':snmp_information[1],'MAC':mac,'OS':soF,'processor':procesadorF,'ram':ram_gb,'disk':disco_gb}
                        
                    print("/********************** IP " + host + " **********************/\n")
                    print(">Nombre: " + toret[host]['name'])
                    print('>MAC: ' + toret[host]['MAC'])
                    print(">S.O.: " + toret[host]['OS'])
                    print(">Procesador: " + toret[host]['processor'])
                    print(">Tamanho total RAM (GB): " + toret[host]['ram'])
                    print(">Tamanho total disco (GB): " + toret[host]['disk'])
                    print("\n")
                    
                    # Writes a new row into csv file with the information of the scanned IP
                    output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])
                
                #Close the csv file
                output.close()
            
            self.cont_times = self.cont_times + 1
            # If the number of times that scan has to be executed is reached, calculate periodic scan results
            if self.cont_times == times:
                print('========> CSV file built and closed')
                print('')
                
                #Gets csv information
                info = read_csv(csv_name)
                info_keys = info.keys()

                # Groups IPs by its MAC direction
                mac_ips = self.__build_mac_ips(info)

                # Builds network graph
                self.__build_graph(mac_ips)
                print('')
                print('========> Network graph created correctly')
                print('')

                # Builds pdf output file
                writer = PDFWriter(lang='esp',output_directory=self.folder_name)
                mac_ips_keys = mac_ips.keys()

                for mac in mac_ips_keys:
                    ip_keys = mac_ips[mac]['IP'].keys()
                    writer.append_info(
                        {'Direccion MAC':mac},
                        [[ip,info[ip]['name'],so,info[ip]['processor'],info[ip]['ram'],info[ip]['disk']] for ip in ip_keys for so in mac_ips[mac]['IP'][ip]],
                        ['IP','Nombre','Sistema Operativo','Procesador','Memoria RAM (GB)','Espacio alamacenamiento disco (GB)'],
                        [3, 2.5, 4, 3, 4, 4]
                    )
                writer.write_document()

                print('========> PDF file created correctly')
                print('')

                # Takes the time when the scan began and the time when it finished. Then calculate the days, 
                # hours, minutes and seconds that the scan lasted.
                start = self.start_time
                finish = datetime.now()
                start_datetime = datetime(start.year, start.month, start.day, start.hour, start.minute, start.second)
                finish_datetime = datetime(finish.year, finish.month, finish.day, finish.hour, finish.minute, finish.second)
                required_time = finish_datetime - start_datetime
                seconds = required_time.seconds
                minutes = (seconds // 60) % 60
                hours = seconds // 3600

                print('')
                print('-------> Periodic scan has finished <--------')
                print('')
                print('*********** PERIODIC SCAN RESULTS ***********')
                print('')
                print('Required time: ' + str(required_time.days) + ' days ' + str(hours) + ' hours ' + str(minutes) + ' minutes')
                print('Alive IPs: ' + str(len(info_keys)) + '')
                print('')
                print('*********************************************')
                sys.exit()
    
    def __build_mac_ips(self,dic):
        """
        Builds a diccionary that contains MACs as keys and a list containing a dictionary for each position 
        that contains an IP and its O.S., for each MAC.

            :param dic: A dictionary that contains IPs as keys with their information.
            :type dic: dict
            :return: A dictionary which contains all IPs grouped by MAC
            :rtype: dict
        """
        
        # Gets the items of the dictionary that is passed as parameter
        dic_items = dic.items()
        # Creates a new dictionary to store IPs and its O.S. grouped by MAC
        mac_ips = {}

        for ip, info in dic_items:
            # If mac_ips is empty store the first MAC with its IP ans O.S. 
            # If not, checks if other IP has the same MAC as one of the stored
            if mac_ips == {}:
                for mac_info in info['MAC'].keys():
                    mac_ips[mac_info] = {'IP':{ip:[]}}
                    for os_mac in info['MAC'][mac_info]:
                        mac_ips[mac_info]['IP'][ip].append(os_mac)
            else:
                #Gets the keys of mac_ips and info dictionary
                mac_ips_keys = mac_ips.keys()
                mac_info_keys = info['MAC'].keys()
                
                for mac in mac_info_keys:
                    # If mac is in mac_ips dictionary, add new IPs with their O.S. into the corresponding mac key
                    # If not creates a new key with the mac and store its IPs with their O.S.
                    if mac in mac_ips_keys:
                        for os_mac in info['MAC'][mac]:
                            mac_ips[mac]['IP'][ip].append(os_mac)
                    else:
                        for mac_info in mac_info_keys:
                            mac_ips[mac_info] = {'IP':{ip:[]}}
                            for os_mac in info['MAC'][mac_info]:
                                mac_ips[mac_info]['IP'][ip].append(os_mac)
        
        mac_ips_keys = mac_ips.keys()
        
        # For each mac, show the mac with their IPs
        for key in mac_ips_keys:
            values = mac_ips[key]['IP'].keys()
            
            for i,_ in enumerate(values):
                print('')
                print('***** MAC ' + key + ' *****')
                print('>IP: ' + values[i])

        # Return mac_ips dictionary
        return mac_ips
    
    def __build_graph(self,mac_ips):
        """
        Build a network graph that represents all the alive ips grouped by MAC. When the construction ends,
        it creates an output png image containing the network graph.

            :param mac_ips: A dictionary that contains ips with its O.S. grouped by MAC(key).
            :type mac_ips: dict
        """
        
        #Gets the local ip from the selected interface
        local_ip = getLocalIpByInterface(self.interface)
        #Gets the mac_ips keys
        macs = mac_ips.keys()

        # Creates different lists to store the different types of nodes and edges
        linux = []
        windows = []
        ios = []
        printer = []
        router = []
        others = []
        first_edges = []
        second_edges = []
        mac_nodes = []

        # Build the graph
        G = nx.Graph()
        
        # Change the size of the png image
        fig = plt.figure(figsize=(30,30))

        # Adds nodes and edges between nodes
        G.add_node('localhost')

        for mac in macs:
            # For each mac gets all IPs
            ips_keys = mac_ips[mac]['IP'].keys()

            # If IPs are different than local ip adds MAC nodes and edges between MACs and loclahost
            if local_ip not in ips_keys:
                mac_nodes.append(mac)
                G.add_node(mac)
                G.add_edge('localhost',mac,weight=1,length=4)
                first_edges.append(('localhost',mac))

            ips = []
            
            for ip in ips_keys:
                # For each recovered IP checks if is different than local. Then check what type of device is each IP
                # and add it to the corresponding list
                if ip != local_ip:
                    os_information = mac_ips[mac]['IP'][ip]
                    
                    if len(os_information) > 1:
                        for i,os in enumerate(os_information):
                            aux = ip + ' -- ' + str(i)
                            ips.append(aux)
                            os_separate = os.split()

                            if 'Linux' in os_separate:
                                linux.append(aux)
                            elif 'Windows' in os_separate:
                                windows.append(aux)
                            elif 'Apple' in os_separate:
                                ios.append(aux)
                            elif 'printer' in os_separate:
                                printer.append(aux)
                            elif 'router' in os_separate:
                                router.append(aux)
                            else:
                                others.append(aux)
                    else:
                        ips.append(ip)
        
                        for os in os_information:
                            os_separate = os.split()

                            if 'Linux' in os_separate:
                                linux.append(ip)
                            elif 'Windows' in os_separate:
                                windows.append(ip)
                            elif 'Apple' in os_separate:
                                ios.append(ip)
                            elif 'printer' in os_separate:
                                printer.append(ip)
                            elif 'router' in os_separate:
                                router.append(ip)
                            else:
                                others.append(ip)
            
            # Add IPs as nodes
            G.add_nodes_from(ips)
            
            #Add edges between IPs and their MAC
            for ip in ips:
                G.add_edge(mac,ip,weight=1,length=4)
                second_edges.append((mac,ip))

        pos = nx.spring_layout(G)

        #Draw nodes into the graph
        nx.draw_networkx_nodes(G,pos,['localhost'],node_size=600,node_shape='o',node_color='gold')
        nx.draw_networkx_nodes(G,pos,mac_nodes,node_size=600,node_shape='o',node_color='skyblue',label='MAC')
        nx.draw_networkx_nodes(G,pos,linux,node_size=600,node_shape='o',node_color='chartreuse', label='O.S. Linux')
        nx.draw_networkx_nodes(G,pos,windows,node_size=600,node_shape='o',node_color='blue',label='O.S. Windows')
        nx.draw_networkx_nodes(G,pos,ios,node_size=600,node_shape='o',node_color='grey',label='O.S. iOs')
        nx.draw_networkx_nodes(G,pos,printer,node_size=600,node_shape='o',node_color='crimson',label='Printer')
        nx.draw_networkx_nodes(G,pos,router,node_size=600,node_shape='o',node_color='red',label='Router')
        nx.draw_networkx_nodes(G,pos,others,node_size=600,node_shape='o',node_color='magenta',label='Others')
        #Draw edges between nodes into the graph
        nx.draw_networkx_edges(G,pos,first_edges,width=2,edge_color='black',label='1 hoop')
        nx.draw_networkx_edges(G,pos,second_edges,width=2,edge_color='black',style='dashed',label='0 hoop')
        #Draw node labels
        nx.draw_networkx_labels(G,pos)

        # Count the number of the columns that graph label should have
        columns = 0
        if linux != []:
            columns = columns + 1
        if windows != []:
            columns = columns + 1
        if ios != []:
            columns = columns + 1
        if printer != []:
            columns = columns + 1
        if router != []:
            columns = columns + 1
        if others != []:
            columns = columns + 1
        
        columns = columns + 3

        # Remove the graph axis
        plt.axis('off')
        # Set margins
        plt.margins(0.1)
        #plt.legend(loc=1,numpoints=1,borderpad=2,labelspacing=2.5)
        plt.legend(loc=9, bbox_to_anchor=(0.5, -0.1),ncol=columns)

        # Gets current date and time
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Store the graph as a png image
        plt.savefig('data/' + self.folder_name + '/' + self.file_name + '_' + current_datetime + '.png',bbox_inches="tight")

    def build_graph_from_csv(self):
        """
        Builds a network graph from an existing csv file.
        """

        #The route of the csv file
        csv_name = 'data/' + self.folder_name + '/' + self.file_name + '.csv'
        
        # If csv file exists read its information, groups IPs by MAC and build the network graph. 
        # If not, print an error message.
        if os.path.isfile(csv_name):
            # Read the csv information
            csv_info = read_csv(csv_name)
            
            #Groups IPs by MAC direction
            mac_ips = self.__build_mac_ips(csv_info)
            #Build network graph
            self.__build_graph(mac_ips)

            print('')
            print('-------> The construction of the graph has finished <--------')
            print('')
        else:
            print('File does not exist!')
            print('')

    
    def __output_csv_name(self):
        """
        Builds the route where csv output files will be stored.

            :return: The route where csv files will be stored.
            :rtype: str
        """

        #Gets the current datetime from de system
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Return the route
        return 'data/' + self.folder_name + '/' + self.file_name + '_' + current_datetime + '.csv'
            
        
