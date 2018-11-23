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
def plot_cdf_with_data(data):
    #http://stanford.edu/~raejoon/blog/2017/05/16/python-recipes-for-cdfs.html
    num_bins = 10
    counts, bin_edges = np.histogram (data, bins=num_bins)
    cdf = np.cumsum (counts)
    plt.plot (bin_edges[1:], cdf/cdf[-1])    


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
counter = 0
for ts, buf in pcap:
    if (counter > 50000):
        break
    
    counter += 1

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
        
        #do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        #more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        #fragment_offset = ip.off & dpkt.ip.IP_OFFMASK 
        
        #print ('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
                  #(inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)  )          
    

#translate flows remaining in moving flow lists to flow objects and add to flow list
for key in moving_tcp_flows:
    map_data = moving_tcp_flows[key]
    f = pd.FlowData(map_data[1])
    completed_tcp_flows.append(f)    

for key in moving_udp_flows:
    map_data = moving_udp_flows[key]
    f = pd.FlowData(map_data[1])
    completed_udp_flows.append(f)  



print('printing set...')
    
for key in link_layer_dict:
    print(key, link_layer_dict[key])

print('------------------------------')
for key in network_layer_dict:
    print(key, network_layer_dict[key])
 
print('------------------------------')   
for key in transport_layer_dict:
    print(key, transport_layer_dict[key])    
    
print('------------------------------')

for flow in completed_tcp_flows:
    print(flow)

for flow in completed_udp_flows:
    print(flow)

# Get the top 3 largest TCP flows in terms of packet number
top3_in_packet_num = sorted(completed_tcp_flows, key=lambda flowData:flowData.total_packets)[-3:]

# Get the top 3 largest TCP flows in terms of total byte size
top3_in_byteSize = sorted(completed_tcp_flows, key=lambda flowData:flowData.total_bytes)[-3:]

# Get the top 3 largest TCP flows in terms of duration
top3_in_duration = sorted(completed_tcp_flows, key=lambda flowData:flowData.duration)[-3:]

'''
print(len(moving_tcp_flows))
print(len(moving_udp_flows))

max_ts_diff = 0
for flow in moving_tcp_flows:
    last_ts = moving_tcp_flows[flow][0]
    first_ts = moving_tcp_flows[flow][1][0].ts
    if (last_ts - first_ts > max_ts_diff):
        max_ts_diff = last_ts - first_ts
        
    #print(moving_tcp_flows[flow][1][0], last_ts - first_ts)
print(max_ts_diff)

max_ts_diff = 0
for flow in moving_udp_flows:
    last_ts = moving_udp_flows[flow][0]
    first_ts = moving_udp_flows[flow][1][0].ts
    if (last_ts - first_ts > max_ts_diff):
        max_ts_diff = last_ts - first_ts
    
    #print(moving_udp_flows[flow][1][0], last_ts - first_ts)
print(max_ts_diff)
'''

#plot_cdf_with_data(all_packet_sizes)
#plot_cdf_with_data(tcp_packet_sizes)

#plot_cdf_with_data(udp_header_sizes)