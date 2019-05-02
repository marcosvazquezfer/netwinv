import netifaces

interfaces = netifaces.interfaces()

def dec_to(num, sistema = 2):

  valores_hexa = {10:'A', 11:'B', 12:'C', 13:'D', 14:'E', 15:'F'}

  if (sistema > 1 and sistema < 17):

    valor_ret = []

    while num:

      num, residuo = divmod(num, sistema)
      valor_ret.append(valores_hexa[residuo]) if (residuo > 9) else valor_ret.append(str(residuo))

    return ''.join(valor_ret[::-1])

  return 'Verifica que el sistema al que deseas convertir sea valido'

def selectInterface():
    
    for i in range(len(interfaces)):

        print(str(i+1) + ") " + interfaces[i])

    resp = int(raw_input("Chosen option: "))
    resp -= 1

    print("You have chosen: " + interfaces[resp])

    return resp

def getIpMascByInterface():
    
    interface = selectInterface()

    ipMask = ""

    #Se captura la informacion de la interfaz
    datos = netifaces.ifaddresses(interfaces[interface])
    #Se captura la lista de parametros que tiene la interface
    variables = datos.keys()

    #Se obtiene la direccion mac
    mac = datos[netifaces.AF_LINK][0]['addr']
    
    if netifaces.AF_INET in variables:
        ip = datos[netifaces.AF_INET][0]['addr']
        mascara = datos[netifaces.AF_INET][0]['netmask']
        masc = mascara.split()

        masF = ""
        
        for i in range(len(mascara)):
            if mascara[i] == ".":
                masc = mascara.replace("."," ")
                masF = masc.split()
                
        binaryList=[]

        for i in masF:
            num = int(i)
            
            if dec_to(num,2) == '':
                binaryList.append('00000000')
            else:
                binaryList.append(dec_to(num,2))

        binary = ''.join(binaryList)
        cont = 0
        
        for i in binary:
            if int(i) == 0:
                cont += 1
        
        maskDec = 32 - cont
        
        ipF = ""
        
        for i in range(len(ip)):
            if ip[i] == ".":
                ip2 = ip.replace("."," ")
                ipF = ip2.split()
                
        binaryList2=[]

        for i in ipF:
            num = int(i)
            
            binaryIpList = []
                
            if dec_to(num,2) == '':
                binaryList2.append('00000000')
            else:
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
        netIpBin = binary2[0:maskDec] + zeros
        netIpDec = str(int(str(netIpBin[0:8]),2)) + '.' + str(int(str(netIpBin[8:16]),2)) + '.' + str(int(str(netIpBin[16:24]),2)) + '.' + str(int(str(netIpBin[24:32]),2))
        ipMask = netIpDec + '/' + str(maskDec)

    return [ipMask,interfaces[interface]]

def getLocalIpByInterface(interf):

    return netifaces.ifaddresses(interf)[netifaces.AF_INET][0]['addr']
