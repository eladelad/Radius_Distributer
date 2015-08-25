import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from radiusattr import RadiusAttr
from radiusext import RadiusExt
import pprint
import time
import multiprocessing
import cPickle

debug = False
print_size = False

if debug: count = 2000
else: count = 0

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

class PicklablePacket:
    """A container for scapy packets that can be pickled (in contrast
    to scapy packets themselves)."""
    def __init__(self, pkt):
        self.contents = str(pkt)
        self.time = pkt.time

    def __call__(self):
        """Get the original scapy packet."""
        pkt = Ether(self.contents)
        pkt.time = self.time
        return pkt

def queue_packet(Packet):
	if IP in Packet and UDP in Packet:
                if Packet[UDP].dport == 1813:
			p = PicklablePacket(Packet)
			queue.put(p)

class Distributer(multiprocessing.Process):
	def __init__(self, q):
		multiprocessing.Process.__init__(self)
		self.q = q
	
	def distribute(self, Packet):
		dst = self.check_receivers(Packet)
		self.dup_pkt(Packet, dst)
	
	def dup_pkt(self, pkt, dst):
	        if pkt[IP].dst == listen_ip:
	                pkts = []
			pkt = PicklablePacket(pkt)
	                for ip in dst:
	                        #pkt2 = copy.deepcopy(pkt)
				pkt2 = cPickle.loads(cPickle.dumps(pkt, -1))
				pkt2 = pkt2()
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
	
	def Get_NAS_IP(self, D):
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
	
	def check_receivers(self, Packet):
		Packet[UDP].decode_payload_as(Radius)
        	nas_ip = self.Get_NAS_IP(Packet[Radius].payload)
	        ptk_ips = array.array('B',[172, 16, 1])
	        if debug: print time.time()
	        if nas_ip[0:3] == ptk_ips:
	                return ptk_forti
	        else:
	                return drp_forti
		
	def run(self):
		proc_name = self.name
		while True:
			if print_size: print self.q.qsize()
			p = self.q.get()
			p = p()
			if debug: print p.summary()
			if p is None:
				if debug: print proc_name
			else:
				self.distribute(p)


if __name__ == '__main__':
	queue = multiprocessing.Queue()
	num_readers = multiprocessing.cpu_count()
	readers = [ Distributer(queue) for i in xrange(num_readers) ]
	for d in readers:
		d.start()

	filter = "dst " + listen_ip + " and udp and dst port "+radius_port
	if debug: print filter
	pkts = sniff(prn=queue_packet, filter=filter, store=0, count=count, iface=listen_int)
