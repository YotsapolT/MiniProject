from scapy.all import *

#get all network interfaces
# print(type(conf.ifaces)) 

# a = sniff(count=50, iface="Intel(R) Ethernet Connection (14) I219-V")
# a = sniff(count=20, iface="Ethernet", filter="udp")
# a.show()
# sniff(iface="Ethernet", prn=lambda x: x.show(), count=5)
r = rdpcap('./capture01.pcap')
# print(get_if_addr("Intel(R) Ethernet Connection (14) I219-V"))
# r = sniff(offline='capture01.pcap')
# r.plot(lambda x: x.id)
# r.show()
packet04_l2 = r[10]
# packet04_l2_0 = r[0]
# len(packet04_l2)
# packet04_l3 = packet04_l2.payload
# packet04_l4 = packet04_l3.payload
packet04_l2.show()
# print(len(packet04_l4.payload))
# print(type(packet04_l3.payload) is scapy.layers.inet.TCP)
# print(str(packet04_l2).find("UDP"))

# ls(tmp)
# print(type(tmp))
# pkt = r[5]
# pkt.show()
# pkt.show2()
# pkt.sprintf()
# ls(pkt)
# hexdump(pkt)

# lsc() #show fn.
