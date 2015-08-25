from scapy.all import *
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
        pprint.pprint(pkt)
	#print pkt[radius]
        print "==================="
        if pkt[IP].dst == "10.1.100.56":
                for ip in ips:
                        pkt2 = copy.deepcopy(pkt)
                        pkt2[IP].dst = ip
                        pkt2[Ether].dst = None
                        #print "Packet1:",pkt[IP].dst,"Packet2:",pkt2[IP].dst
                        send(pkt2)
        print "==================="

pkts = sniff(prn=dup_pkt, filter="port 1813", store=0, count=2)

