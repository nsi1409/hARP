from scapy.all import *


def arp_query(pdst):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=pdst), timeout=2)
	outp = {}
	for an in ans:
		send, recv = an
		mac_addr = recv.src
		local_ip = send.pdst
		outp[mac_addr] = local_ip
		#print(f'local: {local_ip}, mac: {mac_addr}')
	return outp

def find_mac(mac, pdst):
	mac_map = arp_query(pdst)
	try:
		return mac_map[mac]
	except:
		return 'not found'

if __name__ == '__main__':
	#print(arp_query('192.168.0.0/24'))
	#print(arp_query('192.168.0.12'))
	print(find_mac('34:13:e8:60:d1:82', '192.168.0.12'))
