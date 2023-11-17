from scapy.all import *

#get all network interfaces
# print(type(conf.ifaces.data))
# ifaceList = []
# for key in conf.ifaces.data:
#     ifaceList.append(conf.ifaces.data[key].name)

# print(ifaceList)

# a = sniff(count=5, iface="Ethernet")
# wrpcap("tmp.pcap", a)
# r = rdpcap('tmp.pcap')
# r.summary()

# print(str(a[0].show))

# a = sniff(count=20, iface="Ethernet", filter="udp")
# a.show()
# sniff(iface="Ethernet", prn=lambda x: x.show(), count=5)
# r = rdpcap('./capture01.pcap')
# print(get_if_addr("Intel(R) Ethernet Connection (14) I219-V"))
r = sniff(offline='result.pcap')
# r.plot(lambda x: x.id)
# r.show()
# packet04_l2 = r[10]
# packet04_l2_0 = r[0]
# len(packet04_l2)
# packet04_l3 = packet04_l2.payload
# packet04_l4 = packet04_l3.payload
# packet04_l2.show()
# print(len(packet04_l4.payload))
# print(type(packet04_l3.payload) is scapy.layers.inet.TCP)
# print(str(packet04_l2).find("UDP"))

# ls(tmp)
# print(type(tmp))
pkt = r[62]
pkt.show()
# pkt.show2()
# pkt.sprintf()
# ls(pkt)
# hexdump(pkt)

# lsc() #show fn.



# packet = r[3]
# for packet in r:
#     print(packet.show())

# def getProtocol(pkt):
#     if(str(pkt.payload.payload.sport) == '53' or (pkt.payload.payload.dport) == '53'):
#         return 'DNS'
#     else:
#         if str(pkt.payload.proto) == '6':
#             return 'TCP'
#         else:
#             return 'UDP'
        
# print(str(packet[0].payload.src) + " " +
#       str(packet[0].payload.payload.sport) + " " +
#       str(packet[0].payload.dst) + " " +
#       str(packet[0].payload.payload.dport) + " " +
#       getProtocol(packet[0]) + " " +
#       str(len(packet[0])) + " " +
#       "Information"
#       )
