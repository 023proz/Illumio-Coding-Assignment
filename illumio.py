

class PortIpRange:
    '''
    check if port or ip_address is valid
    '''
    def __init__(self, port_lo, port_hi, ip_lo, ip_hi):
        self.port_lo = port_lo
        self.port_hi = port_hi
        self.ip_lo = ([int(i) for i in ip_lo.split('.')])
        self.ip_hi = ([int(i) for i in ip_hi.split('.')])

    def port_contains(self, port):
        if port >= self.port_lo and port <= self.port_hi:
            return True
        else:
            return False 

    def ip_contains(self, ip_address):
        ip_tuple = ([int(i) for i in ip_address.split('.')])

        if ip_tuple >= self.ip_lo and ip_tuple <= self.ip_hi:
            return True
        else:
            return False


class Firewall:
    def __init__(self, path):

        self.rules = { 'inbound' :  {'tcp' : set(), 'udp' : set()},
                       'outbound' : {'tcp' : set(), 'udp' : set()}
                     }

        file = open(path)

        for line in file:
            direction, protocol, port, ip = line.split(',')
            
            if direction == 'direction': #If the line is the header of the csv then skip the line
                continue
            
            if '-' in port: # If the port is a range
                port_lo, port_hi = int(port.split('-')[0]), int(port.split('-')[1])
                if '-' in ip: # If the port is a range
                    ip_lo, ip_hi = ip.split('-')[0], ip.split('-')[1]
                else:
                   ip_lo, ip_hi = ip, ip
            else:
                port_lo, port_hi = int(port), int(port)
                if '-' in ip:
                    ip_lo, ip_hi = ip.split('-')[0], ip.split('-')[1]
                else:
                    ip_lo, ip_hi = ip, ip
            self.rules[direction][protocol].add(PortIpRange(port_lo, port_hi, ip_lo, ip_hi))
                        
        file.close()           
            
        
    def accept_packet(self, direction, protocol, port, ip):
        try:
            for port_ip in self.rules[direction][protocol]:
                if port_ip.port_contains(port) and port_ip.ip_contains(ip):
                    return True
            return False
        except KeyError: # If KeyError occurs, then return False
            return False

if __name__ == '__main__':

    fw = Firewall("fw.csv")
    try:
        assert(fw.accept_packet("inbound", "udp", 53, "192.168.2.1") == True)
        assert(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11") == True)
        assert(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2") == False)
        assert(fw.accept_packet("inbound", "udp", 24, "52.12.48.92") == False)

        assert(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2") == True)
        assert(fw.accept_packet("outbound", "tcp", 19999, "192.168.10.11") == True)
        assert(fw.accept_packet("inbound", "udp", 53, "192.168.1.1") == True)
        assert(fw.accept_packet("outbound", "udp", 999, "52.12.48.92") == False)

        assert(fw.accept_packet("inbound", "udp", 53, "192.168.1.0") == False)
        assert(fw.accept_packet("inbound", "udp", 53, "192.168.2.5") == True)
        assert(fw.accept_packet("inbound", "udp", 53, "192.169.2.5") == False)
        assert(fw.accept_packet("outbound", "udp", 53, "192.168.2.5") == False)
        assert(fw.accept_packet("inbound", "tcp", 53, "192.168.2.5") == False)

        assert(fw.accept_packet("inbound", "tcp", 3000, "192.169.1.2") == True)
        assert(fw.accept_packet("inbound", "tcp", 4000, "192.169.2.5") == True)
        assert(fw.accept_packet("inbound", "tcp", 4000, "192.169.2.4") == True)
        assert(fw.accept_packet("inbound", "tcp", 2999, "192.169.2.4") == False)
        
        print ("all cases passed")
    except AssertionError:
        print ("AssertionError")
