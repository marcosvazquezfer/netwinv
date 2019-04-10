from pysnmp import hlapi

class Snmpwalk:
    '''
    COMENTAR
    '''
    
    def __init__(self,list_oids):
        self.__list_oids = list_oids
        
    def list_oids(self):
        return self.__list_oids

    def get(self,target, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        '''
        COMENTAR
        '''
        
        handler = hlapi.getCmd(
            engine,
            credentials,
            hlapi.UdpTransportTarget((target, port)),
            context,
            *self.__construct_object_types(self.__list_oids)
        )
        return self.__fetch(handler, 1)[0]

    def __construct_object_types(self,list_of_oids):
        '''
        COMENTAR
        '''
        
        object_types = []
        for oid in list_of_oids:
            object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
        return object_types

    def __fetch(self,handler, count):
        '''
        COMENTAR
        '''
        
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
        '''
        COMENTAR
        '''
        
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
