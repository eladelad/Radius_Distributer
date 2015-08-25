from scapy.all import *
from radiusattr import RadiusAttr
from radiusext import RadiusExt
import pprint
import time

debug = True

listen_ip = "192.168.0.1"
host_ip = "10.0.0.138"
radius_port = "1813"

listen_int = "eth0"
send_int = "eth1"

ptk_forti = [
"10.0.0.3",
]

drp_forti = [
"10.1.0.3",
]

def dup_pkt(pkt, dst):
        if pkt[IP].dst == listen_ip:
		pkts = []
                for ip in dst:
                        pkt2 = copy.deepcopy(pkt)
                        pkt2[IP].dst = ip
			pkt2[IP].src = host_ip
                        pkt2[Ether].dst = None
                        pkt2[Ether].src = None
			del pkt2[IP].chksum
			del pkt2[UDP].chksum
			pkts.append(pkt2)
                        #print "Packet1:",pkt[IP].dst,"Packet2:",pkt2[IP].dst
                sendp(pkts,verbose=debug, iface=send_int)
		if debug: print time.time()
        	if debug: print "Sent"

def Analyze_Packet(Packet):
	if IP in Packet and UDP in Packet:
		if Packet[UDP].dport == 1813:
			Packet[UDP].decode_payload_as(Radius)
			nas_ip = Get_NAS_IP(Packet[Radius].payload)
			ptk_ips = array.array('B',[172, 16, 1])
			if debug: print time.time()
			if nas_ip[0:3] == ptk_ips: 
				dup_pkt(Packet, ptk_forti)
			else: 
				dup_pkt(Packet, drp_forti)


def Get_NAS_IP(D):
	Data = str(D)
	data_len = len(Data)
	curr_len =0
	AVP_list = []
	while (curr_len + 2 <= data_len):
	    try:	    
		result = array.array('B',Data)
		avp_type = result[curr_len+0]
		if avp_type == 4:
			return result[curr_len+2:curr_len+6]
		if avp_type == 1 and debug:
			 print "AVP[%d] Type: %d (User-Name) Value: %s" % (1, avp_type, "".join(map(chr,result[curr_len+2:curr_len+15])))
		avp_len = result[curr_len+1]
		curr_len += avp_len
	    except:
		print "Exception"
		pass 
	return []

filter = "dst " + listen_ip + " and udp and dst port "+radius_port
if debug: print filter
if debug: count = 2000 
else: count = 0
pkts = sniff(prn=Analyze_Packet, filter=filter, store=0, count=count, iface=listen_int)
