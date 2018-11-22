class PacketData:
    def __init__(self, src_ip, dest_ip, src_port, dest_port, protocol, ts, size, h_size, d_size):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.ts = ts
        self.size = size
        self.h_size = h_size
        self.d_size = d_size
    
    def flow_keys(self):
        key1 = str(self.src_ip) + "|" + str(self.dest_ip) + "|" + str(self.src_port) + "|" + str(self.dest_port) + "|" + self.protocol
        key2 = str(self.dest_ip) + "|" + str(self.src_ip) + "|" + str(self.dest_port) + "|" + str(self.src_port) + "|" + self.protocol
        keys = [key1, key2]
        return keys
    
    def __str__(self):
        return str(self.src_ip) + "|" + str(self.dest_ip) + "|" + str(self.src_port) + "|" + str(self.dest_port) + "|" + self.protocol + '|' + str(self.ts) + "|" + str(self.size) + '|' + str(self.h_size) + '|' + str(self.d_size)
    
class FlowData:
    def __init__(self, pd_list):
        if (len(pd_list) <= 0):
            return None
        
        pkt = pd_list[0]
        self.flow_key = pkt.flow_keys()[0]
        self.protocol = pkt.protocol
        self.pd_list = pd_list
        self.total_packets = len(pd_list)
        self.total_bytes = sum(p.size for p in pd_list)
        
        total_d_size = sum(p.d_size for p in pd_list)
        if (total_d_size <= 0):
            self.overhead_ratio = 9999
        else:
            self.overhead_ratio = float(sum(p.h_size for p in pd_list)) / float(total_d_size)
            
        #still need to determine final state by looping through packets to look for SYN, ACK, etc
        #need to add in the TCP headers into the packet object
        
    def __str__(self):
        return self.flow_key + '___' + str(self.protocol) + '___' + str(self.total_packets) + '___' + str(self.total_bytes) + '___' + str(self.overhead_ratio)