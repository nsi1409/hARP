from scapy.all import *


def listen(num_packets=40, prefix=''):
	ips = set()
	def packet_callback(packet):
		try:
			ips.add(packet[IP].src)
			ips.add(packet[IP].dst)
		except:
			pass
	capture = sniff(count=num_packets, prn=packet_callback)
	ips = [item for item in ips if item.startswith(prefix)]
	return ips


if __name__ == '__main__':
	print(listen())
