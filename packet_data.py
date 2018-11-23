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
        
        self.fin = 0
        self.syn = 0
        self.rst = 0
        self.ack = 0
    
    def flow_keys(self):
        key1 = str(self.src_ip) + "|" + str(self.dest_ip) + "|" + str(self.src_port) + "|" + str(self.dest_port) + "|" + self.protocol
        key2 = str(self.dest_ip) + "|" + str(self.src_ip) + "|" + str(self.dest_port) + "|" + str(self.src_port) + "|" + self.protocol
        keys = [key1, key2]
        return keys
    
    def __str__(self):
        return str(self.src_ip) + "|" + str(self.dest_ip) + "|" + str(self.src_port) + "|" + str(self.dest_port) + "|" + self.protocol + '|' + str(self.ts) + "|" + str(self.size) + '|' + str(self.h_size) + '|' + str(self.d_size)
    
    def set_tcp_headers(self, fin, syn, rst, ack):
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.ack = ack
        
    def print_tcp_header(self):
        if (self.protocol == 'TCP'):
            print(('_FIN_' if self.fin else '') + ('_SYN_' if self.syn else '') + ('_RST_' if self.rst else '') + ('_ACK_' if self.ack else ''))
    
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
        
        
        pkt1 = pd_list[0]
        pkt_lst = pd_list[len(pd_list) - 1]
        self.duration = pkt_lst.ts - pkt1.ts
        
        total_d_size = sum(p.d_size for p in pd_list)
        if (total_d_size <= 0):
            self.overhead_ratio = 9999
        else:
            self.overhead_ratio = float(sum(p.h_size for p in pd_list)) / float(total_d_size)
            
        self.tcp_class = ''
        
        init_syn_sent = False
        init_syn_received = False
        init_fin_sent = False
        init_fin_received = False
        rst_received = False
        
        #determining class for TCP flow
        if (self.protocol == 'TCP'):
            for pkt in self.pd_list:
                if (pkt.syn):
                    init_syn_sent = True
                if (init_syn_sent and pkt.syn and pkt.ack) :
                    init_syn_received = True
                if (pkt.fin):
                    init_fin_sent = True
                if (init_fin_sent and pkt.fin and pkt.ack):
                    init_fin_received = True
                if (pkt.rst):
                    rst_received = True
                
            if (init_syn_sent and not(init_syn_received)):
                self.tcp_class = 'Request'
            if (init_fin_sent and init_fin_received):
                self.tcp_class = 'Finished'
            if (rst_received):
                self.tcp_class = 'Reset'
            if (self.tcp_class == ''):
                self.tcp_class = 'Ongoing'
            #no case for failed since file size is always less than 5 mins
        
    def __str__(self):
        return self.flow_key + '___' + str(self.protocol) + '___' + str(self.total_packets) + '___' + str(self.total_bytes) + '___' + str(self.overhead_ratio) + '___' + str(self.duration) + '___' + self.tcp_class