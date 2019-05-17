import nmap
import csv
import os
import os.path
import sys
import pandas as pd
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt

from datetime import datetime

from lib.core.Snmpwalk import *
from lib.helpers.ip_helper import *
from lib.helpers.csv_helper import *

class Scanner:
    """
    This class is an implementation of a nmap scanner and file exporter.

    It is the responsible for executing a scan in the indicated network trying to identify alive IPs, 
    MAC network, operating system, name associated with the IP, processor, total siza of RAM and
    total size of disk.
    
    When the scan finishes, the class creates a file_name output file and a png image which tries to represent
    the network, exporting them to the indicated output directory.

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
        """
        
        active_ips = self.nmap.scan(self.ip,arguments="-sP")
        
        hosts = self.nmap.all_hosts()
        
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
        
        snmp_scanning = self.nmap.scan(host, arguments="-sU -p 161")
        snmp_scanning_keys = snmp_scanning['scan'].keys()
        
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
        
        scanning = self.nmap.scan(host,arguments="-O")
        os_scanning_keys = scanning['scan'].keys()
        
        return [scanning,os_scanning_keys]
    
    def scan(self):
        """
        Perfom the scan of the indicated network doing all needed scans. When the scan finishes, a csv file
        and a network graph are created. All the obtain information will be printed in the terminal.
        """

        self.start_time = datetime.now()

        #Diccionary where the information will be stored
        toret = {}
        #
        csv_name = self.__output_csv_name()
        #csv file is open in write mode
        output_file = csv.writer(open(csv_name,'wb'))

        #Ping scanning is done and its information is recovered
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
            
            output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])
            
        mac_ips = self.__build_mac_ips(toret)
        self.__build_graph(mac_ips)

        start = self.start_time
        finish = datetime.now()
        start_datetime = datetime(start.year, start.month, start.day, start.hour, start.minute, start.second)
        finish_datetime = datetime(finish.year, finish.month, finish.day, finish.hour, finish.minute, finish.second)
        required_time = finish_datetime - start_datetime
        seconds = required_time.seconds
        minutes = (seconds // 60) % 60
        hours = seconds // 3600

        print('')
        print('Scan has finished')
        print('')
        print('*************** SCAN RESULTS ****************')
        print('**                                         **')
        print('** Required time: ' + str(required_time.days) + ' days ' + str(hours) + ' hours ' + str(minutes) + ' minutes **')
        print('** Alive IPs: ' + str(len(toret.keys())) + '                            **')
        print('**                                         **')
        print('*********************************************')

    def periodic_scan(self,times):
        """
        Perfom the periodic scan of the indicated network, the indicated number of times,
        doing all needed scans. When the scan finishes, a csv file and a network graph are created. 
        All the obtain information will be printed in the terminal.

            :param times: The number of times that scan will be executed
            :type scan_type: int
        """

        #Diccionary where the information will be stored
        toret = {}
        #The route of the csv file
        csv_name = 'data/' + self.folder_name + '/' + self.file_name + '.csv'
        
        #If the number of times that scan should be executed have not been yet reached
        if self.cont_times < times:
            #If csv file exists
            if os.path.isfile(csv_name):
                #csv file information is recovered
                csv_info = read_csv(csv_name)
                csv_info_keys = csv_info.keys()

                #csv file is open in write mode but adding new information at the end of the file
                output = open(csv_name,'a')
                output_file = csv.writer(output)

                #Ping scanning is done and its information is recovered
                ping_scanning = self.__ping_scanning()
                active_ips = ping_scanning[0]
                hosts = ping_scanning[1]
                
                for host in hosts:
                    print('Scanning ' + host + '...')
                    addresses_keys = active_ips['scan'][host]['addresses'].keys()
                    os_scanning = self.__os_scanning(host)
                    os_scanning_res = os_scanning[0]
                    os_scanning_keys = os_scanning[1]
                    
                    if addresses_keys[0] == 'mac':
                        mac = active_ips['scan'][host]['addresses']['mac']
                    else:
                        mac = 'Unknown'

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

                    if host in csv_info_keys and csv_info[host]['MAC'] == mac and csv_info[host]['OS'] != so:
                        snmp_information = []
                        snmp_scanning = self.__snmp_port_scanning(host)
                        snmp_port_scanning = snmp_scanning[0]
                        snmp_port_scanning_keys = snmp_scanning[1]

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
                    
                        output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])
                    
                    elif host in csv_info_keys and csv_info[host]['MAC'] != mac:
                        snmp_information = []
                        snmp_scanning = self.__snmp_port_scanning(host)
                        snmp_port_scanning = snmp_scanning[0]
                        snmp_port_scanning_keys = snmp_scanning[1]

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
                    
                        output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])
                
                output.close()
                #mac_ips = self.__build_mac_ips(toret)
            else:
                toret = {}
                csv_name = 'data/' + self.folder_name + '/' + self.file_name + '.csv'
                self.start_time = datetime.now()
                
                output = open(csv_name,'wb')
                output_file = csv.writer(output)

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
                    
                    output_file.writerow([host,toret[host]['MAC'],toret[host]['name'],toret[host]['OS'],toret[host]['processor'],toret[host]['ram'],toret[host]['disk']])
                
                output.close()
                #mac_ips = self.__build_mac_ips(toret)
                
            self.cont_times = self.cont_times + 1
            if self.cont_times == times:
                info = read_csv(csv_name)
                info_keys = info.keys()
                organized_keys = sorted(info_keys)

                output = open(csv_name,'wb')
                output_file = csv.writer(output)

                for key in organized_keys:
                    output_file.writerow([key,info[key]['MAC'],info[key]['name'],info[key]['OS'],info[key]['processor'],info[key]['ram'],info[key]['disk']])
                
                output.close()

                mac_ips = self.__build_mac_ips(info)
                self.__build_graph(mac_ips)

                start = self.start_time
                finish = datetime.now()
                start_datetime = datetime(start.year, start.month, start.day, start.hour, start.minute, start.second)
                finish_datetime = datetime(finish.year, finish.month, finish.day, finish.hour, finish.minute, finish.second)
                required_time = finish_datetime - start_datetime
                seconds = required_time.seconds
                minutes = (seconds // 60) % 60
                hours = seconds // 3600

                print('')
                print('Periodic scan has finished')
                print('')
                print('******** PERIODIC SCAN RESULTS ********')
                print('**** Required time: ' + str(required_time.days) + ' days ' + str(hours) + ' hours ' + str(minutes) + ' minutes ****')
                print('**** Alive IPs: ' + str(len(info_keys)) + ' ****')
                print('***************************************')
                sys.exit()
        else:
            print('TERMINE')
            sys.exit()
        #self.__build_graph(toret)
    
    def __build_mac_ips(self,dic):
        """
        Builds a diccionary that contains MACs as keys and a list of IPs with its O.S. for each MAC.

            :param dic: A dictionary that contains IPs as keys with their information.
            :type dic: dict
            :return: A dictionary which contains all IPs grouped by MAC
            :rtype: dict
        """
        
        dic_keys = dic.keys()
        mac_ips = {}
        
        for key in dic_keys:
            if mac_ips == {}:
                mac_ips[dic[key]['MAC']] = [{'IP':key,'OS':dic[key]['OS']}]
            else:
                mac_ips_keys = mac_ips.keys()

                for mac in mac_ips_keys:
                    if(mac == dic[key]['MAC']):
                        mac_ips[mac].append({'IP':key,'OS':dic[key]['OS']})
                    else:
                        mac_ips[dic[key]['MAC']] = [{'IP':key,'OS':dic[key]['OS']}]
        
        mac_ips_keys = mac_ips.keys()
        
        for key in mac_ips_keys:
            values = mac_ips[key]
            for i in range(len(values)):
                print('')
                print('/**** MAC ' + key + ' ****/')
                print('>IP: ' + values[0]['IP'])

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

        linux = []
        windows = []
        ios = []
        printer = []
        others = []
        first_edges = []
        second_edges = []

        # ips_list = []
        # #local_ip_list = []

        # for key in dic_keys:
        #     if(key != local_ip):
        #         ips_list.append(key)

        # for i in range(len(ips_list)):
        #     local_ip_list.append(local_ip)

        # Build a dataframe with your connections
        # df = pd.DataFrame({ 'from':local_ip_list, 'to':ips_list})
        # df
        
        # # Build your graph
        # G=nx.from_pandas_edgelist(df, 'from', 'to', create_using=nx.Graph() )
        G = nx.Graph()
        
        #Custom the nodes:
        fig = plt.figure(figsize=(20,20))
        G.add_node('localhost')
        G.add_nodes_from(macs)
        for mac in macs:
            G.add_edge('localhost',mac,weight=1,length=4)
            first_edges.append(('localhost',mac))
            ips = []
            
            for i in range(len(mac_ips[mac])):
                ips.append(mac_ips[mac][i]['IP'])
                so_information = mac_ips[mac][i]['OS'].split()

                if 'Linux' in so_information:
                    linux.append(mac_ips[mac][i]['IP'])
                elif 'Windows' in so_information:
                    windows.append(mac_ips[mac][i]['IP'])
                elif 'Apple' in so_information:
                    ios.append(mac_ips[mac][i]['IP'])
                elif 'printer' in so_information:
                    printer.append(mac_ips[mac][i]['IP'])
                else:
                    others.append(mac_ips[mac][i]['IP'])
                
            G.add_nodes_from(ips)

            for ip in ips:
                G.add_edge(mac,ip,weight=1,length=4)
                second_edges.append((mac,ip))

        pos = nx.spring_layout(G)

        #Draw nodes into the graph
        nx.draw_networkx_nodes(G,pos,['localhost'],node_size=600,node_shape='o',node_color='gold')
        nx.draw_networkx_nodes(G,pos,macs,node_size=600,node_shape='o',node_color='skyblue',label='MAC')
        nx.draw_networkx_nodes(G,pos,linux,node_size=600,node_shape='o',node_color='chartreuse', label='O.S. Linux')
        nx.draw_networkx_nodes(G,pos,windows,node_size=600,node_shape='o',node_color='blue',label='O.S. Windows')
        nx.draw_networkx_nodes(G,pos,ios,node_size=600,node_shape='o',node_color='grey',label='O.S. iOs')
        nx.draw_networkx_nodes(G,pos,printer,node_size=600,node_shape='o',node_color='crimson',label='Printer')
        nx.draw_networkx_nodes(G,pos,others,node_size=600,node_shape='o',node_color='magenta',label='Others')
        #Draw edges between nodes into the graph
        nx.draw_networkx_edges(G,pos,first_edges,width=2,edge_color='black',label='1 hoop')
        nx.draw_networkx_edges(G,pos,second_edges,width=2,edge_color='black',style='dashed',label='0 hoop')
        #Draw node labels
        nx.draw_networkx_labels(G,pos)

        columns = 0
        if linux != []:
            columns = columns + 1
        if windows != []:
            columns = columns + 1
        if ios != []:
            columns = columns + 1
        if printer != []:
            columns = columns + 1
        if others != []:
            columns = columns + 1
        
        columns = columns + 3

        plt.axis('off')
        plt.margins(0.1)
        #plt.legend(loc=1,numpoints=1,borderpad=2,labelspacing=2.5)
        plt.legend(loc=9, bbox_to_anchor=(0.5, -0.1),ncol=columns)

        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        #plt.savefig('data/' + self.folder_name + '/' + self.file_name + '_' + current_datetime + '.png')
        plt.savefig('data/' + self.folder_name + '/' + self.file_name + '_' + current_datetime + '.png',bbox_inches="tight")

    def build_graph_from_csv(self):
        """
        Builds a network graph from an existing csv file.
        """

        #The route of the csv file
        csv_name = 'data/' + self.folder_name + '/' + self.file_name + '.csv'
        
        if os.path.isfile(csv_name):
            csv_info = read_csv(csv_name)
            
            mac_ips = self.__build_mac_ips(csv_info)
            self.__build_graph(mac_ips)
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

        return 'data/' + self.folder_name + '/' + self.file_name + '_' + current_datetime + '.csv'
            
        
