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
        
        self.seq_val = -1
        self.ack_val = -1
    
    def flow_keys(self):
        key1 = str(self.src_ip) + "|" + str(self.dest_ip) + "|" + str(self.src_port) + "|" + str(self.dest_port) + "|" + self.protocol
        key2 = str(self.dest_ip) + "|" + str(self.src_ip) + "|" + str(self.dest_port) + "|" + str(self.src_port) + "|" + self.protocol
        keys = [key1, key2]
        return keys
    
    def host_pairs(self):
        hp1 = str(self.src_ip) + "|" + str(self.dest_ip)
        hp2 = str(self.dest_ip) + "|" + str(self.src_ip)
        hps = [hp1, hp2]
        return hps
    
    def __str__(self):
        return str(self.src_ip) + "|" + str(self.dest_ip) + "|" + str(self.src_port) + "|" + str(self.dest_port) + "|" + self.protocol + '|' + str(self.ts) + "|" + str(self.size) + '|' + str(self.h_size) + '|' + str(self.d_size)
    
    def set_tcp_headers(self, fin, syn, rst, ack):
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.ack = ack
        
    def set_tcp_values(self, seq, ack):
        self.seq_val = seq
        self.ack_val = ack
        
    def print_tcp_header(self):
        if (self.protocol == 'TCP'):
            print(('_FIN_' if self.fin else '') + ('_SYN_' if self.syn else '') + ('_RST_' if self.rst else '') + ('_ACK_' if self.ack else ''))
            print("seq num is %d" % self.seq_val + "___ ack num is %d" % self.ack_val)
    
class FlowData:
    def __init__(self, pd_list):
        if (len(pd_list) <= 0):
            return None
        
        pkt = pd_list[0]
        self.host_pairs = pkt.host_pairs()
        self.flow_key1 = pkt.flow_keys()[0]
        self.flow_key2 = pkt.flow_keys()[1]
        self.protocol = pkt.protocol
        self.pd_list = pd_list
        self.total_packets = len(pd_list)
        self.total_bytes = sum(p.size for p in pd_list)
        
        ts_acc = -1
        self.inter_arrival_times = []
        for p in pd_list:
            if (ts_acc < 0):
                ts_acc = p.ts
            else:
                ts_diff = p.ts - ts_acc
                self.inter_arrival_times.append(ts_diff)
                ts_acc = p.ts
        
        
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
    

class RTT:
    def __init__(self, rtt, ts, flow_key):
        self.rtt = rtt
        self.ts = ts
        self.flow_key = flow_key

def measure_rtt_flow(flow):
    packets = flow.pd_list
    
    #initializing structures
    first_pkt = packets[0]
    flow_key1 = first_pkt.flow_keys()[0]
    flow_key2 = first_pkt.flow_keys()[1]
    
    flow_key_map = {}
    flow_key_map[flow_key1] = {}
    flow_key_map[flow_key2] = {}
    
    rtt_map = {}
    #map stores list of lists, element 0 = sample RTT measurements, element 1 = estimated RTT measurements
    rtt_map[flow_key1] = [[], []]
    rtt_map[flow_key2] = [[], []]
    
    rto = 1
    srtt = 0
    rttvar = 0
    G = 0.000001 #one microsecond as suggested in the discussion boards
    first_measurement_made = False
    
    for pkt in packets:
        direction = ''
        reverse = ''
        
        if (flow_key1 == pkt.flow_keys()[0]):
            direction = flow_key1
            reverse = flow_key2
        else:
            direction = flow_key2
            reverse = flow_key1
        
        #add seq to direction map if not in it... ignore otherwise
        if (not (pkt.seq_val in flow_key_map[direction])):
            flow_key_map[direction][pkt.seq_val] = pkt.ts
        
        #remove from reverse if ack in map & then calc RTT...ignore otherwise
        if (pkt.ack_val in flow_key_map[reverse]):
            rtt = pkt.ts - (flow_key_map[reverse])[pkt.ack_val]
            
            
            #print ('SAM_RTT =',rtt, '___for flow=',direction,'__@ts=',pkt.ts)
            sam_rtt = RTT(rtt, pkt.ts, direction)
            rtt_map[direction][0].append(sam_rtt)
            
            if not(first_measurement_made):
                first_measurement_made = True
                srtt = rtt
                rttvar = rtt / 2.0
                rto = srtt + max(G, 4 * rttvar)
            else:
                rttvar = (1 - 0.25) * rttvar + 0.25 * abs(srtt - rtt)
                srtt = (1 - 0.125) * srtt + 0.125 * rtt
                rto = srtt + max(G, 4.0 * rttvar)
            
            #if (rto < 1.0):
                #rto = 1.0
            
            est_rtt = RTT(rto, pkt.ts, direction)
            rtt_map[direction][1].append(est_rtt)
            #print ('EST_RTT =',rto, '___for flow=',direction,'__@ts=',pkt.ts)
            
            del (flow_key_map[reverse])[pkt.ack_val]
            
    
    
    
    #print(direction,'___',flow_key_map[direction])
    #print(reverse,'____',flow_key_map[reverse])
    #print('___-------____')
    
    return rtt_map

class HostPair:
    def __init__(self, key, flow_list):
        self.key = key
        self.flow_list = flow_list
        self.length = len(flow_list)