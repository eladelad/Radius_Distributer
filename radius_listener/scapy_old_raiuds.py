from scapy.all import *
from radiusattr import RadiusAttr
from radiusext import RadiusExt
import pprint

ips = [
"127.0.0.1",
"127.0.0.2",
"127.0.0.3",
"127.0.0.4",
"127.0.0.5",
"127.0.0.6",
"127.0.0.7",
]

def dup_pkt(pkt):
        #pprint.pprint(pkt)
	Radius_Packet_Counter(pkt,1813)
	#print pkt[radius]
        if pkt[IP].dst == "10.1.100.":
                for ip in ips:
                        pkt2 = copy.deepcopy(pkt)
                        pkt2[IP].dst = ip
                        pkt2[Ether].dst = None
                        #print "Packet1:",pkt[IP].dst,"Packet2:",pkt2[IP].dst
                        send(pkt2)
        print "==================="

def Analyze_Packet(Packet):
	if IP in Packet and UDP in Packet:
		if Packet[UDP].dport == 1813:
			Packet[UDP].decode_payload_as(Radius)
			#RadiusPacket = RadiusExt(code=Packet[Radius].code,authenticator=Packet[Radius].authenticator,id=Packet[Radius].id)
			#avp_list_packet = RadiusPacket.Get_AVPList(Packet[Radius].payload)
			Radius_Packet_Counter(Packet,1813)
			#pprint.pprint(avp_list_packet)
			#print Get_NAS_IP(Packet[Radius].payload)
			nas_ip = Get_NAS_IP(Packet[Radius].payload)
			ptk_ips = array.array('B',[212, 25, 114])
			if nas_ip[0:3] == ptk_ips: site = 'ptk' 
			else: site = 'drp'
			print site

def Get_NAS_IP(D):
	#input: radius packet payload
	#output: list of AVPs
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
		avp_len = result[curr_len+1]
		curr_len += avp_len
	    except:
		print "Exception"
		pass 
	return []


def Radius_Packet_Counter(Packet,port):
    global r_accept
    global r_reject 
    global r_other
    if IP in Packet and UDP in Packet:
	print "ip and udp in packet"
	if Packet[UDP].dport == port:
	    print "sport is port"
	    Packet[UDP].decode_payload_as(Radius)
	    RadiusPacket = RadiusExt(code=Packet[Radius].code,authenticator=Packet[Radius].authenticator,id=Packet[Radius].id)
	    print "Received Radius Packet......"
	    RadiusPacket.Display_Packet(Packet)
		
	    if Packet[Radius].code == 2:
		r_accept += 1
	    elif Packet[Radius].code == 3:
		r_reject += 1
	    else:
		r_other += 1

r_accept = 0
r_reject = 0
r_other = 0

pkts = sniff(prn=Analyze_Packet, filter="udp and port 1813", store=0, count=1)


