from flask import Flask, request
from scapy.all import *
# from flask_socketio import SocketIO, send

app = Flask(__name__)
# socketio = SocketIO(app, cors_allowed_origins='*')

def sendMessage(pkt):
    message = str(pkt.payload.src) + " " 
    + str(pkt.payload.payload.sport) + " " 
    + str(pkt.payload.dst) + " " 
    + str(pkt.payload.payload.dport) + " " 
    + getProtocol(pkt) + " " 
    + str(len(pkt)) + " " 
    + "Information"

    send(message)

def getPacketInfo(pkt):
    try:
        pktInfo = ""
        pktInfo += ("Source IP: " + str(pkt.payload.src) + " ") 
        pktInfo += ("Source port: " + str(pkt.payload.payload.sport) + " ") 
        pktInfo += ("Destination IP: " + str(pkt.payload.dst) + " ") 
        pktInfo += ("Destination port: " + str(pkt.payload.payload.dport) + " ")
        pktInfo += ("Protocol: " + getProtocol(pkt) + " ")
        pktInfo += ("Length: " + str(len(pkt)))
        return pktInfo
    except AttributeError:
        print('attr error')
        pktInfo = ""
        pktInfo += ("Source IP: " + str(pkt.payload.src) + " ")
        pktInfo += ("Destination IP: " + str(pkt.payload.dst) + " ")
        pktInfo += ("Protocol(IP): " + str(pkt.payload.proto) + " ")
        return pktInfo

def getProtocol(pkt):
    if(str(pkt.payload.payload.sport) == '53' or (pkt.payload.payload.dport) == '53'):
        return 'DNS'
    else:
        if str(pkt.payload.proto) == '6':
            return 'TCP'
        else:
            return 'UDP'

def allow_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {
        'pcap',
        'cap'
    }

def getNetworkInterface():
    interfaceNames = conf.ifaces
    return interfaceNames

@app.route('/', methods=['GET', 'POST'])
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'GET':
        return {'text': "this is Dashboard!"}
    else:
        if 'file' not in request.files:
            return {'error': "No file provided"}, 400
        
        imported_file = request.files['file']
        
        if imported_file == "":
            return {'error': "No file selected"}, 400
        if imported_file and allow_file(imported_file.filename):   
            packetFromFile = rdpcap(imported_file)
            packetList = []
            noPacket = 0
            for packet in packetFromFile:
                noPacket += 1
                packetList.append('No.:' + str(noPacket) + ' ' + getPacketInfo(packet))

            streamDict = {}
            protocolDict = {}
            try:
                for row in packetList:
                    packetNo = row.split("No.:")[1].split()[0].strip()
                    sourceIP = row.split("Source IP:")[1].split()[0].strip()
                    sourcePort = row.split("Source port:")[1].split()[0].strip()
                    destinationIP = row.split("Destination IP:")[1].split()[0].strip()
                    destinationPort = row.split("Destination port:")[1].split()[0].strip()


                    if bool(streamDict):
                        sameStream = 0
                        for key in streamDict:
                            if (sourceIP in streamDict[key]['IP']) and (destinationIP in streamDict[key]['IP']) and (sourcePort in streamDict[key]['Port']) and (destinationPort in streamDict[key]['Port']):
                                oldValue = streamDict[key]['PacketNo.']
                                streamDict[key]['PacketNo.'] = oldValue + ',' + packetNo
                                sameStream = 1
                                break
                        if sameStream == 0:
                            newKey = 'stream#' + str(len(streamDict) + 1)
                            streamDict[newKey] = {
                                'IP': sourceIP + ', ' + destinationIP,
                                'Port': sourcePort + ', ' + destinationPort,
                                'PacketNo.': packetNo
                            }
                    else:
                        streamDict['stream#1'] = {
                            'IP': sourceIP + ', ' + destinationIP,
                            'Port': sourcePort + ', ' + destinationPort,
                            'PacketNo.': packetNo
                        }

                    protocol = row.split("Protocol:")[1].split()[0].strip()
                    if protocol in protocolDict:
                        protocolDict[protocol] += 1
                    else:
                        protocolDict[protocol] = 1
            except IndexError:
                print('idx error')
            packetList.append(protocolDict)
            packetList.append(streamDict)
            return packetList
        else:
            return {'error': "Invalid file format, allow file types are .pacp or .cap"}, 400
        
@app.route('/packet_capture', methods=['GET', 'POST'])
def packet_capture():
    if request.method == 'GET':
        interfaceList = []
        for key in conf.ifaces.data:
            interfaceList.append(conf.ifaces.data[key].name)
        return {'interfaceList': interfaceList}
    else:
        # sniffer = AsyncSniffer(iface=request.form['interfaceName'], prn=lambda msg: sendMessage(msg))
        # if request.form['stop'] == "0":
        #     sniffer.start()
        # else:
        #     result = sniffer.stop()
        #     wrpcap("result.pcap", result)

        packetList = sniff(iface=request.form['interfaceName'], count=int(request.form['count']), filter='ip')
        resultList = []
        for packet in packetList:
            resultList.append(getPacketInfo(packet))
        wrpcap("result.pcap", packetList)
        return resultList

        
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=10000)