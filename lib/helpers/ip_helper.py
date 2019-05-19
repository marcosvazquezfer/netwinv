import netifaces

interfaces = netifaces.interfaces()

def dec_to(num, system = 2):
    """
    Convert a decimal number to the indicated system.

        :param num: The number to convert
        :param system: The system to convert the number
        :type num: int
        :type system: int
        :return: The number in the indicated system
        :rtype: in
    """

    # Hexadecimal values
    hexa_values = {10:'A', 11:'B', 12:'C', 13:'D', 14:'E', 15:'F'}

    # If the system is between 1 and 17, executes the conversion. If not print an error message
    if (system > 1 and system < 17):

        ret_value = []

        while num:
            num, rest = divmod(num, system)
            ret_value.append(hexa_values[rest]) if (rest > 9) else ret_value.append(str(rest))

        return ''.join(ret_value[::-1])

    return 'Check if the system to convert is valid!'

def selectInterface():
    """
    Shows all the interfaces for the user, to choose one

        :return: the chosen option
        :rtype: int
    """

    values = []
    for i in range(len(interfaces)):

        print(str(i+1) + ") " + interfaces[i])
        values.append(str(i+1))

    resp = raw_input("Chosen option: ")
    while resp not in values:
        resp = raw_input("Chosen option: ")

    resp = int(resp)
    resp -= 1

    print('')
    print("You have chosen: " + interfaces[resp])

    return resp

def getIpMascByInterface():
    """
    Gets the network IP and its mask from the IP associated to the chosen interface.

        :return: a list containing the network IP and the mask, and the interface.
        :rtype: list
    """
    
    # Gets the interface
    interface = selectInterface()

    ipMask = ""

    # Gets the interface information
    interface_info = netifaces.ifaddresses(interfaces[interface])
    # Gets the list of the parameters that the interface has
    variables = interface_info.keys()

    # Gets the MAC direction
    mac = interface_info[netifaces.AF_LINK][0]['addr']
    
    # If direction is in variables, gets all the information and calculate he network IP
    if netifaces.AF_INET in variables:
        # Gets the IP
        ip = interface_info[netifaces.AF_INET][0]['addr']
        # Gets the mask
        mask_of_ip = interface_info[netifaces.AF_INET][0]['netmask']

        # Converts the mask in a list
        masc = mask_of_ip.split()
        masF = ""
        
        for i in range(len(mask_of_ip)):
            # If find a point, replace it with a space
            if mask_of_ip[i] == ".":
                masc = mask_of_ip.replace("."," ")
                masF = masc.split()
                
        binaryList=[]

        for i in masF:
            num = int(i)
            
            # If the conversion is empty, store 0. If not, store the conversion
            if dec_to(num,2) == '':
                binaryList.append('00000000')
            else:
                binaryList.append(dec_to(num,2))

        # Put all the elements contained in the list together
        binary = ''.join(binaryList)
        cont = 0
        
        for i in binary:
            # If the number is 0, adds 1 to the cont
            if int(i) == 0:
                cont += 1
        
        # Calculates the mask in decimal system
        maskDec = 32 - cont
        
        ipF = ""
        
        for i in range(len(ip)):
            # If find a point, replace it with a space
            if ip[i] == ".":
                ip2 = ip.replace("."," ")
                ipF = ip2.split()
                
        binaryList2=[]

        for i in ipF:
            num = int(i)
            
            binaryIpList = []
            
            # If the result of the conversion is empty, store 0. If not calculate the number to store.
            if dec_to(num,2) == '':
                binaryList2.append('00000000')
            else:
                # If the length of the result of the conversion is less than 8, puts as many 0 as the difference
                #  and store it. If not, store the result of the conversion.
                if len(dec_to(num,2)) < 8:
                    length = 8 - len(dec_to(num,2))
                    
                    for j in range(length):
                        binaryIpList.append('0')
                        
                    binaryIpList.append(dec_to(num,2))
                    binaryIp = ''.join(binaryIpList)
                    binaryList2.append(binaryIp)
                else:
                    binaryList2.append(dec_to(num,2))
            
        zeroList = []
        
        for i in range(32-maskDec):
            zeroList.append('0')
            
        zeros = ''.join(zeroList)
        binary2 = ''.join(binaryList2)

        # Gets the network IP in binary
        netIpBin = binary2[0:maskDec] + zeros
        # Gets the network IP in decimal
        netIpDec = str(int(str(netIpBin[0:8]),2)) + '.' + str(int(str(netIpBin[8:16]),2)) + '.' + str(int(str(netIpBin[16:24]),2)) + '.' + str(int(str(netIpBin[24:32]),2))
        # Concatenate the network IP and the mask
        ipMask = netIpDec + '/' + str(maskDec)

    # Return the IP with the mask and the interface
    return [ipMask,interfaces[interface]]

def getLocalIpByInterface(interf):
    """
    Return the local IP from an interface

        :param interf: the interface to get the local IP
        :type interf: str

        :return: The local IP
        :rtype: str
    """

    return netifaces.ifaddresses(interf)[netifaces.AF_INET][0]['addr']
