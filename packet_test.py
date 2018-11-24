import dpkt
import datetime
import socket
import numpy as np
import matplotlib.pyplot as plt

import packet_data as pd
from dpkt.compat import compat_ord #this only used in the below helper functions for printing data

#these two are helper functions copied from the examples on dpkt.readthedocs.io, may not be needed but should be cited
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)



#-----------------------------------------
def plot_cdf_with_data(data, title, uselog=False):
    #http://stanford.edu/~raejoon/blog/2017/05/16/python-recipes-for-cdfs.html
    num_bins = 20
    counts, bin_edges = np.histogram (data, bins=num_bins)
    cdf = np.cumsum (counts)
    plt.figure()
    plt.title(title)
    plt.plot (bin_edges[1:], cdf/cdf[-1])   
    if (uselog):
        plt.xscale('log')

def draw_rtt_time(rtt_list, ts_list, title, uselog=False):
    plt.figure()
    plt.title(title)
    plt.plot (rtt_list, ts_list)  
    if (uselog):
        plt.xscale('log')    

def generate_rtt_cdf(top3_flow_list, title):
    print('Generating {0} flow RTT CDFs...'.format(title))
    acc = 0
    while (acc < len(top3_in_packet_num)):
        rank = len(top3_in_packet_num) - acc
        sample_flow1_title = 'Sample RTT A->B for {0} #{1}'.format(title, rank)
        sample_flow2_title = 'Sample RTT B->A for {0} #{1}'.format(title, rank)
        est_flow1_title = 'Estimated RTT A->B for {0} #{1}'.format(title, rank)
        est_flow2_title = 'Estimated RTT B->A for {0} #{1}'.format(title, rank)
        
        flow = top3_in_packet_num[acc]
        f_rtt_map = pd.measure_rtt_flow(flow)
        
        #for first RTT for flow A->B
        sample_rtt_list_fk1 = f_rtt_map[flow.flow_key1][0]
        est_rtt_list_fk1 = f_rtt_map[flow.flow_key1][1]
        
        s_rtt_val_list = [rttobj.rtt for rttobj in sample_rtt_list_fk1]
        s_ts_val_list = [rttobj.ts for rttobj in sample_rtt_list_fk1]
        draw_rtt_time(s_ts_val_list, s_rtt_val_list, sample_flow1_title)
        
        est_rtt_val_list = [rttobj.rtt for rttobj in est_rtt_list_fk1]
        est_ts_val_list = [rttobj.ts for rttobj in est_rtt_list_fk1]
        draw_rtt_time(est_ts_val_list, est_rtt_val_list, est_flow1_title)    
        
        #for second RTT for flow B->A
        sample_rtt_list_fk2 = f_rtt_map[flow.flow_key2][0]
        est_rtt_list_fk2 = f_rtt_map[flow.flow_key2][1]
        
        s_rtt_val_list = [rttobj.rtt for rttobj in sample_rtt_list_fk2]
        s_ts_val_list = [rttobj.ts for rttobj in sample_rtt_list_fk2]
        draw_rtt_time(s_ts_val_list, s_rtt_val_list, sample_flow2_title)
        
        est_rtt_val_list = [rttobj.rtt for rttobj in est_rtt_list_fk2]
        est_ts_val_list = [rttobj.ts for rttobj in est_rtt_list_fk2]
        draw_rtt_time(est_ts_val_list, est_rtt_val_list, est_flow2_title)     
        
        acc += 1    

path_to_file='univ1_pt9'
f = open(path_to_file,'rb')
pcap = dpkt.pcap.Reader(f)


link_layer_dict = {}
network_layer_dict = {}
transport_layer_dict = {}

all_packet_sizes = []
tcp_packet_sizes = []
udp_packet_sizes = []
ip_packet_sizes = []
non_ip_packet_sizes = []

ip_header_sizes = []
tcp_header_sizes = []
udp_header_sizes = []

moving_tcp_flows = {}
moving_udp_flows = {}

completed_tcp_flows = []
completed_udp_flows = []

print('parsing file...')

total_packets = 0
total_bytes = 0

counter = 0
for ts, buf in pcap:
    if (counter > 50000):
        break
    
    #counter += 1
    
    total_packets = total_packets + 1
    total_bytes = total_bytes + len(buf)

    all_packet_sizes.append(len(buf))
    
    isEthernet = False
    
    #link layer counts
    link_key = ''
    if (pcap.datalink() == dpkt.pcap.DLT_EN10MB) :
        link_key = 'Ethernet'
        isEthernet = True
    else :
        link_key = 'Other'
        
    if (link_key in link_layer_dict):
        val = link_layer_dict[link_key]
        #update count
        val[0] = val[0] + 1
        #update total bytes
        val[1] = val[1] + len(buf)
    else :
        link_layer_dict[link_key] = [1, len(buf)]
    
    
    #network layer counts
    if (isEthernet) :
        eth = dpkt.ethernet.Ethernet(buf)
        
        classname = eth.data.__class__.__name__
        if (classname == 'bytes') :
            #skip packets that are do not map to dpkt classes
            continue   
        
        ip = eth.data
        
        isIp = False
        
        ip_key = ''
        if isinstance(eth.data, dpkt.ip.IP):
            isIp = True
            if (ip.p == dpkt.ip.IP_PROTO_ICMP) :
                ip_key = 'ICMP'
            else :
                ip_key = 'IPv4'
            
            ip_header_sizes.append(eth.data.__hdr_len__)
            ip_packet_sizes.append(len(buf))
        else :
            #not ipv4 
            if (eth.type == dpkt.ethernet.ETH_TYPE_IP6):
                isIp = True
                if (ip.p == dpkt.ip.IP_PROTO_ICMP6):
                    ip_key = 'ICMP'
                else :
                    ip_key = 'IPv6'
                    
                ip_header_sizes.append(eth.data.__hdr_len__)
                ip_packet_sizes.append(len(buf))
            else :
                ip_key = 'Other'
                
                non_ip_packet_sizes.append(len(buf))
        
        if (ip_key in network_layer_dict):
            val = network_layer_dict[ip_key]
            #update count
            val[0] = val[0] + 1
            #update total bytes
            val[1] = val[1] + len(buf)
        else :
            network_layer_dict[ip_key] = [1, len(buf)]        
        
        
        if (isIp):
            #checking transport protocol
            
            transport_key = ''
            if (ip.p == dpkt.ip.IP_PROTO_TCP):
                transport_key = 'TCP'
                
                tcp_header_sizes.append(ip.data.__hdr_len__)
                tcp_packet_sizes.append(len(buf))
                
                tcp = ip.data
                h_size = ip.data.__hdr_len__ + eth.data.__hdr_len__ + eth.__hdr_len__
                d_size = len(tcp.data)
                #print ('h_size =',h_size,'d_size =', d_size)
                pk = pd.PacketData(inet_to_str(ip.src), inet_to_str(ip.dst), tcp.sport, tcp.dport, 'TCP', ts, len(buf), h_size, d_size)
                
                fin = 1 if tcp.flags & dpkt.tcp.TH_FIN else 0
                syn = 1 if tcp.flags & dpkt.tcp.TH_SYN else 0
                rst = 1 if tcp.flags & dpkt.tcp.TH_RST else 0
                ack = 1 if tcp.flags & dpkt.tcp.TH_ACK else 0
                
                pk.set_tcp_headers(fin, syn, rst, ack)
                pk.set_tcp_values(tcp.seq, tcp.ack)
                
                keys = pk.flow_keys()
                
                hasKey = False
                for key in keys:
                    if (key in moving_tcp_flows):
                        hasKey = True
                        map_data = moving_tcp_flows[key]
                        
                        #check if over 90 mins since last packet
                        if ((ts - map_data[0]) /60.0/1000 > 90):
                            #construct flow object, save to: completed_tcp_flows
                            #hasKey will still be False
                            
                            #print('90 mins! TCP!', str((ts - map_data[0]) /60.0/1000))
                            
                            f = pd.FlowData(map_data[1])
                            completed_tcp_flows.append(f)                            
                            
                            break
                        
                        #update latest timestamp
                        map_data[0] = ts
                        map_data[1].append(pk)
                
                #dict does not have key or the flow has passed 90 mins since last packet
                if not hasKey:
                    moving_tcp_flows[keys[0]] = [ts, [pk]]
                                
                
            elif (ip.p == dpkt.ip.IP_PROTO_UDP):
                transport_key = 'UDP'
                
                udp_header_sizes.append(ip.data.__hdr_len__)
                udp_packet_sizes.append(len(buf))
                
                udp = ip.data
                h_size = ip.data.__hdr_len__ + eth.data.__hdr_len__ + eth.__hdr_len__
                d_size = len(udp.data)
                #print ('h_size =',h_size,'d_size =', d_size)
                pk = pd.PacketData(inet_to_str(ip.src), inet_to_str(ip.dst), udp.sport, udp.dport, 'UDP', ts, len(buf), h_size, d_size)   
                
                keys = pk.flow_keys()
                
                hasKey = False
                for key in keys:
                    if (key in moving_udp_flows):
                        hasKey = True
                        map_data = moving_udp_flows[key]
                        
                        #check if over 90 mins since last packet
                        if ((ts - map_data[0]) /60.0/1000 > 90):
                            #construct flow object, save to: completed_tcp_flows
                            #hasKey will still be False
                            
                            #print('90 mins! UDP!', str((ts - map_data[0]) /60.0/1000))
                            
                            f = pd.FlowData(map_data[1])
                            completed_udp_flows.append(f)
                            
                            break
                        
                        #update latest timestamp
                        map_data[0] = ts
                        map_data[1].append(pk)
                
                #dict does not have key or the flow has passed 90 mins since last packet
                if not hasKey:
                    moving_udp_flows[keys[0]] = [ts, [pk]]
                
            else :
                transport_key = 'Other'
        
        if (transport_key in transport_layer_dict):
            val = transport_layer_dict[transport_key]
            #update count
            val[0] = val[0] + 1
            #update total bytes
            val[1] = val[1] + len(buf)
        else :
            transport_layer_dict[transport_key] = [1, len(buf)]          
    

#translate flows remaining in moving flow lists to flow objects and add to flow list
for key in moving_tcp_flows:
    map_data = moving_tcp_flows[key]
    f = pd.FlowData(map_data[1])
    completed_tcp_flows.append(f)    

for key in moving_udp_flows:
    map_data = moving_udp_flows[key]
    f = pd.FlowData(map_data[1])
    completed_udp_flows.append(f)  

print('Starting statistics...')

# -- per packet statistics start --
#Table data
print ('Type [packet_count, total_bytes]')
print('Total # packets =',total_packets,', Total # bytes =',total_bytes)
print('------------------------------')

for key in link_layer_dict:
    print(key, link_layer_dict[key],'[{0} {1}]'.format((link_layer_dict[key][0] / float(total_packets)), (link_layer_dict[key][1] / float(total_bytes))))

print('---------------------')
for key in network_layer_dict:
    print(key, network_layer_dict[key],'[{0} {1}]'.format((network_layer_dict[key][0] / float(total_packets)), (network_layer_dict[key][1] / float(total_bytes))))
 
print('---------------------')   
for key in transport_layer_dict:
    print(key, transport_layer_dict[key],'[{0} {1}]'.format((transport_layer_dict[key][0] / float(total_packets)), (transport_layer_dict[key][1] / float(total_bytes))))   

print('------------------------------')

# CDFs for per packet stats
print('Generating per-packet CDFs...')

#plot_cdf_with_data(all_packet_sizes, 'All Packet Sizes')
#plot_cdf_with_data(tcp_packet_sizes, 'TCP Packet Sizes')
#plot_cdf_with_data(udp_packet_sizes, 'UDP Packet Sizes')

#plot_cdf_with_data(ip_packet_sizes, 'IP Packet Sizes')
#plot_cdf_with_data(non_ip_packet_sizes, 'Non-IP Packet Sizes')

#plot_cdf_with_data(ip_header_sizes, 'IP Header Sizes')
#plot_cdf_with_data(tcp_header_sizes, 'TCP Header Sizes')
#plot_cdf_with_data(udp_header_sizes, 'UDP Header Sizes')

print('------------------------------')

# -- per flow statistics --
total_flows = len(completed_tcp_flows) + len(completed_udp_flows)
total_bytes = sum(f.total_bytes for f in completed_tcp_flows) + sum(f.total_bytes for f in completed_udp_flows)

# Flow type
print('TCP', '[{0}, {1}] [{2}, {3}]'.format(len(completed_tcp_flows), sum(f.total_bytes for f in completed_tcp_flows), len(completed_tcp_flows) / float(total_flows), sum(f.total_bytes for f in completed_tcp_flows) / float(total_bytes)))

print('UDP', '[{0}, {1}] [{2}, {3}]'.format(len(completed_udp_flows), sum(f.total_bytes for f in completed_udp_flows), len(completed_udp_flows) / float(total_flows), sum(f.total_bytes for f in completed_udp_flows) / float(total_bytes)))

print('---------------------')

# Flow duration
print('Generating flow duration CDFs...')
all_durations = []
tcp_durations = []
udp_durations = []

for flow in completed_tcp_flows:
    all_durations.append(flow.duration)
    tcp_durations.append(flow.duration)

for flow in completed_udp_flows:
    all_durations.append(flow.duration)
    udp_durations.append(flow.duration)    

#plot_cdf_with_data(all_durations, 'All Flow Durations')
#plot_cdf_with_data(tcp_durations, 'TCP Flow Durations')
#plot_cdf_with_data(udp_durations, 'UDP Flow Durations')

print('------------------------------')

# Flow Size
print('Generating flow sizes CDFs...')
all_flow_sizes = [[], []]
tcp_flow_sizes = [[], []]
udp_flow_sizes = [[], []]

for flow in completed_tcp_flows:
    all_flow_sizes[0].append(flow.total_packets)
    all_flow_sizes[1].append(flow.total_bytes)
    tcp_flow_sizes[0].append(flow.total_packets)
    tcp_flow_sizes[1].append(flow.total_bytes)

for flow in completed_udp_flows:
    all_flow_sizes[0].append(flow.total_packets)
    all_flow_sizes[1].append(flow.total_bytes)
    udp_flow_sizes[0].append(flow.total_packets)
    udp_flow_sizes[1].append(flow.total_bytes)    

#plot_cdf_with_data(all_flow_sizes[0], 'All Flow Packets')
#plot_cdf_with_data(all_flow_sizes[1], 'All Flow Bytes')
#plot_cdf_with_data(tcp_flow_sizes[0], 'TCP Flow Packets')
#plot_cdf_with_data(tcp_flow_sizes[1], 'TCP Flow Bytes')
#plot_cdf_with_data(udp_flow_sizes[0], 'UDP Flow Packets')
#plot_cdf_with_data(udp_flow_sizes[1], 'UDP Flow Bytes')

print('------------------------------')

# InterÅ]packet arrival time
print('Generating flow InterÅ]packet arrival time CDFs...')
all_inter_atimes = []
tcp_inter_atimes = []
udp_inter_atimes = []

for flow in completed_tcp_flows:
    for time in flow.inter_arrival_times:
        all_inter_atimes.append(time)
        tcp_inter_atimes.append(time)

for flow in completed_udp_flows:
    for time in flow.inter_arrival_times:
        all_inter_atimes.append(time)
        udp_inter_atimes.append(time)

#plot_cdf_with_data(all_inter_atimes, 'All Flow Inter-packet Arrival Times')
#plot_cdf_with_data(tcp_inter_atimes, 'TCP Flow Inter-packet Arrival Times')
#plot_cdf_with_data(udp_inter_atimes, 'UDP Flow Inter-packet Arrival Times')


print('------------------------------')

# TCP State
total_flows = len(completed_tcp_flows)
state_map = {}
for flow in completed_tcp_flows:
    if not(flow.tcp_class in state_map):
        state_map[flow.tcp_class] = 1
    else:
        state_map[flow.tcp_class] += 1

for key in state_map:
    print('{0} [Total={1}, {2}]'.format(key, state_map[key], state_map[key] / float(total_flows)))

print('------------------------------')

# --- RTT Estimation ---

# Get the top 3 largest TCP flows in terms of packet number
top3_in_packet_num = sorted(completed_tcp_flows, key=lambda flowData:flowData.total_packets)[-3:]

# Get the top 3 largest TCP flows in terms of total byte size
top3_in_byteSize = sorted(completed_tcp_flows, key=lambda flowData:flowData.total_bytes)[-3:]

# Get the top 3 largest TCP flows in terms of duration
top3_in_duration = sorted(completed_tcp_flows, key=lambda flowData:flowData.duration)[-3:]

# Top 3 in Packet Num
#generate_rtt_cdf(top3_in_packet_num, 'Top 3 in Packet Num')

# Top 3 in Byte Size
#generate_rtt_cdf(top3_in_byteSize, 'Top 3 in Byte Size')

# Top 3 in Duration
#generate_rtt_cdf(top3_in_duration, 'Top 3 in Duration')

print('---------------------') 

# Host Pair stats




print('------------------------------')




# Rest of this doesn't matter



#for flow in top3_in_packet_num:
    #print(flow.flow_key1)
    
#print('------------')
    
#for flow in top3_in_byteSize:
    #print(flow.flow_key1)
    
#print('------------')
        
#for flow in top3_in_duration:
    #print(flow.flow_key1)        

#print('------------------------------')



#flow0 = top3_in_packet_num[0]
#f0_rtt_map = pd.measure_rtt_flow(flow0)

#sample_rtt_list_fk1 = f0_rtt_map[flow0.flow_key1][0]
#est_rtt_list_fk1 = f0_rtt_map[flow0.flow_key1][1]
#print('last sample =',sample_rtt_list_fk1[len(sample_rtt_list_fk1) - 1].rtt,'___','last est =',est_rtt_list_fk1[len(est_rtt_list_fk1) - 1].rtt)

#sample_rtt_list_fk2 = f0_rtt_map[flow0.flow_key2][0]
#est_rtt_list_fk2 = f0_rtt_map[flow0.flow_key2][1]
#print('last sample =',sample_rtt_list_fk2[len(sample_rtt_list_fk2) - 1].rtt,'___','last est =',est_rtt_list_fk2[len(est_rtt_list_fk2) - 1].rtt)