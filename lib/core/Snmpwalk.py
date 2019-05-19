from pysnmp import hlapi

class Snmpwalk:
    """
    Class that gets hardware information from oids from snmp protocol. 
    It implements a similar behaviour as snmpwalk, the snmp application.

        :param list_oids: The list of oids to obtain information
        :type list_oids: list
    """
    
    def __init__(self,list_oids):
        self.__list_oids = list_oids
        
    @property
    def list_oids(self):
        return self.__list_oids

    def get(self,target, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        """
        Gets the value of the indicated oids in the MIB.

            :param target: The ip from which it wants to get the information
            :param credentials: The credentials to authenticate the session
            :param port: The port that we want to obtain the information
            :param engine: The engine of the snmp protocol
            :param context: The context of the snmp protocol
            :type target: srt
            :type credentials: str
            :type protocol: int
            :type engine: str
            :return: The hardware information required
            :rtype: list
        """
        
        handler = hlapi.getCmd(
            engine,
            credentials,
            hlapi.UdpTransportTarget((target, port)),
            context,
            *self.__construct_object_types(self.__list_oids)
        )

        return self.__fetch(handler, 1)[0]

    def __construct_object_types(self,list_of_oids):
        """
        Creates the necessary information for get function from the list of oids, 
        to obtain information from the snmp protocol.
        
            :param list_of_oids: A list that contains oids to obtain hardware information
            :type list_of_oids: list
            :return: A list of objects obtained from the oids to obtain information
            :rtype: list
        """
        
        object_types = []

        for oid in list_of_oids:
            object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))

        return object_types

    def __fetch(self,handler, count):
        """
        Loops on the indicated handler for as many times as count indicates and store the data
        in a list of dictionaries. At the end, return the list of dictionaries.

            :param handler: a handler for the snmp session
            :param count: the number of times that the function should loop the handler
            :type handler: handler
            :type count: int
            :return: A list of dictionaries
            :rtype: list
        """
        
        result = []

        for i in range(count):
            try:
                error_indication, error_status, error_index, var_binds = next(handler)
                if not error_indication and not error_status:
                    items = {}

                    for var_bind in var_binds:
                        items[str(var_bind[0])] = self.__cast(var_bind[1])
                    result.append(items)
                else:
                    raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
            except StopIteration:
                break

        return result

    def __cast(self,value):
        """
        Convert the received data to int, float or string.

            :param value: the obtained data
            :return: data converted to int, float or string
            :rtype: int, float or str
        """
        
        try:
            return int(value)
        except (ValueError, TypeError):
            try:
                return float(value)
            except (ValueError, TypeError):
                try:
                    return str(value)
                except (ValueError, TypeError):
                    pass

        return value
