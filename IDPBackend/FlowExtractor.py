import pyshark
import pandas as pd
import time
import os
import statistics
import asyncio
from .taskmanager import Task
from IDPBackend.models import Flow
from django.db import IntegrityError
import numpy as np
from IDPBackend.models import Status
from IDPBackend.models import TrafficStatus
from IDPBackend.MachineLearningTesting import MachineLearningTesting
import subprocess
from threading import Thread
import socket

def startTestingThread(flowDataFrame):
    thread = Thread(target=MachineLearningTesting, args=(flowDataFrame,))
    thread.start()


def FlowExtractor(interface, capture, captureDuration, IP):
    flows = {}
    streams = {}
    fwdByteCountList = {}
    bwdByteCountList = {}

    fwdPayloadSizes = {}
    bwdPayloadSizes = {}

    fwdUniquePorts = {}

    fwdDelta = {}
    bwdDelta = {}
    startTime = time.time()
    logFilePath = '/var/log/auth.log'
    fwdIFT = {}
    bwdIFT = {}

    try:
        Status.objects.create(status='Sniffer On')
        for packet in capture.sniff_continuously():
            # print(packet)
            currentTime = time.time()

            if currentTime - startTime >= captureDuration:
                break

            flag = ''
            window = 0
            payloadSize = 0
            timeDelta = 0

            if 'ip' in packet and packet is not None:
                outgoing = (packet.ip.src == "149.102.157.168")

                protocol = packet.transport_layer
                if protocol:
                    try:

                        srcPort = packet[protocol].srcport
                        dstPort = packet[protocol].dstport

                        srcIP = packet.ip.src
                        dstIP = packet.ip.dst

                    except AttributeError:
                        continue
                else:
                    continue;

                if outgoing:
                    # My IP address is prioritized as the source, if i am sending.
                    # The receiver is prioritized as the destination.
                    flowID = "{} {} {} {} {}".format(srcIP, srcPort, dstIP, dstPort, protocol)
                    backward = "{} {} {} {} {}".format(dstIP, dstPort, srcIP, srcPort, protocol)
                else:

                    # My IP address is prioritized as the destination, if i am receiving
                    # The sender is prioritized as the source
                    flowID = "{} {} {} {} {}".format(dstIP, dstPort, srcIP, srcPort, protocol)
                    backward = "{} {} {} {} {}".format(srcIP, srcPort, dstIP, dstPort, protocol)

                key = srcIP + dstIP
                fwdUniquePorts.setdefault(key, [])

                if dstPort not in fwdUniquePorts.get(key, []):
                    fwdUniquePorts[key].append(dstPort)

                elapsedTime = 0

                flowID = "{} {} {} {} {}".format(srcIP, srcPort, dstIP, dstPort, protocol)
                backward = ("{} {} {} {} {}".format(dstIP, dstPort, srcIP, srcPort, protocol))

                fwdByteCountList.setdefault(flowID, [])
                bwdByteCountList.setdefault(backward, [])

                fwdDelta.setdefault(flowID, [])
                bwdDelta.setdefault(backward, [])

                fwdPayloadSizes.setdefault(flowID, [])
                bwdPayloadSizes.setdefault(backward, [])

                if flowID not in flows and backward not in flows:
                    flows[flowID] = {

                        'flowID': flowID,
                        'srcIP': srcIP,
                        'dstPort': dstPort,
                        'Unique Ports': len(fwdUniquePorts[key]),
                        'Auth Failures': 0.0,
                        'Origin': "Nowhere",
                        'fwd flags': 0.0,
                        'bwd flags': 0.0,
                        'fwd time delta': 0.0,
                        'bwd time delta': 0.0,
                        'fwd window size': 0.0,
                        'bwd window size': 0.0,
                        'fwd Packet Flow Rate/s': 0.0,
                        'bwd Packet Flow Rate/s': 0.0,
                        'min fwd packet length': 0.0,
                        'max fwd packet length': 0.0,
                        'min bwd packet length': 0.0,
                        'max bwd packet length': 0.0,
                        'fwd meanDelta': 0.0,
                        'fwd varianceDelta': 0.0,
                        'bwd varianceDelta': 0.0,
                        'fwd stdDevDelta': 0.0,
                        'bwd stdDevDelta': 0.0,
                        'fwd variancePayloadSize': 0.0,
                        'bwd variancePayloadSize': 0.0,
                        'Fwd Packet Bytes/s': 0.0,
                        'Bwd Packet Bytes/s': 0.0,
                        'bwd meanDelta': 0.0,
                        'protocol': protocol,
                        'fwd payload size': 0.0,
                        'bwd payload size': 0.0,
                        'fwd packetCount': 0.0,
                        'bwd packetCount': 0.0,
                        'packetCount': 0.0,
                        'total fwd byteCount': 0.0,
                        'total bwd byteCount': 0.0,
                        'fwd flowDuration': 0.0,
                        'bwd flowDuration': 0.0,
                        'fwd meanByteSize': 0.0,
                        'fwd stDevByteSize': 0.0,
                        'fwd varianceByteSize': 0.0,
                        'bwd meanByteSize': 0.0,
                        'bwd stDevByteSize': 0.0,
                        'bwd varianceByteSize': 0.0,
                        'rtt': 0.0,
                        'SYN-Flag count': 0.0,

                        'ACK-Flag count': 0.0,
                        'RST-Flag count': 0.0,
                        'PSH-Flag count': 0.0,
                        'FIN-Flag count': 0.0,
                        'URG-Flag count': 0.0,
                        'CWR-Flag count': 0.0,
                        'ECE-Flag count': 0.0,
                        'Label': 0,

                    }

                if 'TCP' in packet:
                    tcpPacket = packet.tcp

                    window = tcpPacket.window_size
                    timeDelta = tcpPacket.time_delta

                    fwdDelta[flowID].append(float(timeDelta))

                    if hasattr(tcpPacket, 'payload'):
                        payloadSize = len(bytearray.fromhex(tcpPacket.payload.replace(':', '')))

                    tcpStream = packet.tcp.stream
                    packetTimestamp = float(packet.sniff_timestamp)
                    flag = packet.tcp.flags

                    if tcpStream not in streams:
                        streams[tcpStream] = {'PTS': packetTimestamp, 'SYN': False, 'SYN-ACK': False,
                                              'RTT-CHECK': False}

                        if flag == '0x0002':
                            flows[flowID]['SYN-Flag count'] += 1

                            print('SYN flag belonging to', flowID)
                            streams[tcpStream]['synTime'] = float(packet.sniff_timestamp)
                            streams[tcpStream]['SYN'] = True
                    # else:
                    if flag == '0x0012':
                        print('SYN-ACK flag belonging to', flowID)
                        streams[tcpStream]['syn-ackTime'] = float(packet.sniff_timestamp)
                        streams[tcpStream]['SYN-ACK'] = True

                    elapsedTime = packetTimestamp - streams[tcpStream]['PTS']

                if flowID in flows:

                    if flag == '0x008':
                        flows[flowID]['PSH-Flag count'] += 1
                    if flag == '0x0010':
                        flows[flowID]['ACK-Flag count'] += 1
                    if flag == '0x0001':
                        flows[flowID]['FIN-Flag count'] += 1
                    if flag == '0x0040':
                        flows[flowID]['ECE-Flag count'] += 1
                    if flag == '0x0080':
                        flows[flowID]['CWR-Flag count'] += 1
                    if flag == '0x0020':
                        flows[flowID]['URG-Flag count'] += 1
                    if flag == '0x0012':
                        flows[flowID]['RST-Flag count'] += 1

                    flows[flowID]['fwd time delta'] = float(timeDelta)

                    fwdDelta[flowID].append(float(timeDelta))

                    flows[flowID]['Unique Ports'] = len(fwdUniquePorts[key])

                    if not outgoing and os.path.getsize(logFilePath) != 0:
                        # print("auth.log exists.")

                        result = subprocess.run(["grep", "-c", "Failed password", logFilePath], capture_output=True,
                                                text=True)
                        count = int(result.stdout.strip())
                        # print(f"Authentication failure count: {count}")
                        flows[flowID]['Auth Failures'] = count
                    if 'UDP' not in packet:

                        flows[flowID]['fwd flags'] = flag
                        flows[flowID]['fwd payload size'] += payloadSize
                        fwdPayloadSizes[flowID].append(payloadSize)
                        flows[flowID]['fwd window size'] = window

                        if streams[tcpStream]['SYN'] == True and streams[tcpStream]['SYN-ACK'] == True and \
                                streams[tcpStream]['RTT-CHECK'] == False:
                            RTT = streams[tcpStream]['syn-ackTime'] - streams[tcpStream]['synTime']
                            flows[flowID]['rtt'] = RTT
                            streams[tcpStream]['RTT-CHECK'] = True

                    # get statistics for udp also

                    if int(packet.length) < flows[flowID]['min fwd packet length']:
                        flows[flowID]['min fwd packet length'] = int(packet.length)
                    if int(packet.length) > flows[flowID]['max fwd packet length']:
                        flows[flowID]['max fwd packet length'] = int(packet.length)

                    flows[flowID]['fwd flowDuration'] += elapsedTime
                    flows[flowID]['packetCount'] += 1

                    flows[flowID]['fwd packetCount'] += 1
                    flows[flowID]['total fwd byteCount'] += int(packet.length)

                    totalFwdByteCount = flows[flowID]['total fwd byteCount']
                    totalFwdDuration = flows[flowID]['fwd flowDuration']
                    if (totalFwdDuration != 0):
                        fwdByteCountList[flowID].append(int(packet.length))
                        flows[flowID]['Fwd Packet Bytes/s'] = totalFwdByteCount / totalFwdDuration

                    if (flows[flowID]['fwd flowDuration'] != 0):
                        flows[flowID]['fwd meanByteSize'] = flows[flowID]['total fwd byteCount'] / flows[flowID][
                            'fwd packetCount']
                        flows[flowID]['fwd Packet Flow Rate/s'] = flows[flowID]['fwd packetCount'] / flows[flowID][
                            'fwd flowDuration']

                    if (len(fwdByteCountList[flowID]) >= 2):
                        flows[flowID]['fwd stDevByteSize'] = statistics.stdev(fwdByteCountList[flowID])
                        flows[flowID]['fwd varianceByteSize'] = statistics.variance(fwdByteCountList[flowID])

                        if (len(fwdPayloadSizes[flowID]) >= 2):
                            flows[flowID]['fwd variancePayloadSize'] = statistics.variance(fwdPayloadSizes[flowID])

                        flows[flowID]['fwd stdDevDelta'] = np.std(fwdDelta[flowID])
                        flows[flowID]['fwd varianceDelta'] = statistics.variance(fwdDelta[flowID])
                        flows[flowID]['fwd meanDelta'] = statistics.mean(fwdDelta[flowID])

                    elif 'UDP' in packet:
                        flows[flowID]['Unique Ports'] = len(fwdUniquePorts[key])

                        UDPHeaderLength = 8
                        UDPPayloadSize = int(packet.udp.length) - UDPHeaderLength
                        flows[flowID]['fwd payload size'] += UDPPayloadSize

                elif backward in flows:

                    flows[backward]['bwd time delta'] = float(timeDelta)
                    bwdDelta[backward].append(float(timeDelta))

                    if 'UDP' not in packet:
                        flows[backward]['bwd flags'] = flag

                        flows[backward]['bwd window size'] = window
                        flows[backward]['bwd payload size'] += payloadSize
                        bwdPayloadSizes[backward].append(payloadSize)

                        if streams[tcpStream]['SYN'] == True and streams[tcpStream]['SYN-ACK'] == True and \
                                streams[tcpStream]['RTT-CHECK'] == False:
                            RTT = streams[tcpStream]['syn-ackTime'] - streams[tcpStream]['synTime']
                            flows[backward]['rtt'] = RTT
                            streams[tcpStream]['RTT-CHECK'] = True

                    # both UDP and TCP
                    if int(packet.length) < flows[backward]['min bwd packet length']:
                        flows[backward]['min bwd packet length'] = int(packet.length)
                    if int(packet.length) > flows[backward]['max bwd packet length']:
                        flows[backward]['max bwd packet length'] = int(packet.length)

                    flows[backward]['bwd flowDuration'] += elapsedTime
                    flows[backward]['packetCount'] += 1
                    flows[backward]['bwd packetCount'] += 1
                    flows[backward]['total bwd byteCount'] += int(packet.length)

                    totalBwdByteCount = flows[backward]['total bwd byteCount']
                    totalBwdDuration = flows[backward]['bwd flowDuration']
                    if (totalBwdDuration != 0):
                        flows[backward]['Bwd Packet Bytes/s'] = totalBwdByteCount / totalBwdDuration

                    bwdByteCountList[backward].append(int(packet.length))

                    if (flows[backward]['bwd flowDuration'] != 0):
                        flows[backward]['bwd meanByteSize'] = flows[backward]['total bwd byteCount'] / flows[backward][
                            'bwd packetCount']
                        flows[backward]['bwd Packet Flow Rate/s'] = flows[backward]['bwd packetCount'] / \
                                                                    flows[backward]['bwd flowDuration']

                    if 'UDP' in packet:
                        UDPHeaderLength = 8
                        UDPPayloadSize = int(packet.udp.length) - UDPHeaderLength
                        flows[backward]['bwd payload size'] += UDPPayloadSize

                    if (len(bwdByteCountList[backward]) >= 2):

                        flows[backward]['bwd stDevByteSize'] = statistics.stdev(bwdByteCountList[backward])
                        flows[backward]['bwd varianceByteSize'] = statistics.variance(bwdByteCountList[backward])
                        if (len(bwdPayloadSizes[backward]) >= 2):
                            flows[backward]['bwd variancePayloadSize'] = statistics.variance(bwdPayloadSizes[backward])

                        flows[backward]['bwd stdDevDelta'] = statistics.stdev(bwdDelta[backward])
                        flows[backward]['bwd varianceDelta'] = statistics.variance(bwdDelta[backward])
                        flows[backward]['bwd meanDelta'] = statistics.mean(bwdDelta[backward])

        Tasks = Task.get('sniffer')
        if (Tasks != 'off'):
            capture.close()
            subprocess.run(["pkill", "-f", "dumpcap -n -i - -Z none"], check=False)
            if os.path.getsize(logFilePath) != 0:
                subprocess.run(["sudo", "truncate", "-s", "0", logFilePath])
                # print('file removed')

            flowDataFrame = pd.DataFrame.from_dict(flows, orient='index')

            fileExists = os.path.exists('FlowData.csv')

            flowDataFrame.to_csv('FlowData.csv', mode='a', header=not fileExists, index=False)

            FlowUpdater(flowDataFrame, interface, capture, captureDuration, IP)
        else:
            Status.objects.create(status='Sniffer off')
            TrafficStatus.objects.create(status='network monitor not active')
            print('Network Monitor thread terminated.')
    except asyncio.exceptions.CancelledError:

        print("Task(s) Cancelled")
        return 0


def FlowUpdater(flowDataFrame, interface, capture, captureDuration, IP):
    for x, row in flowDataFrame.iterrows():
        try:
            Flow.objects.create(
                flowID=row['flowID'],
                srcIP=row['srcIP'],
                dstPort=row['dstPort'],
                fwdFlags=row['fwd flags'],
                bwdFlags=row['bwd flags'],
                fwdTimeDelta=row['fwd time delta'],
                bwdTimeDelta=row['bwd time delta'],
                fwdWindowSize=row['fwd window size'],
                Origin=row['Origin'],
                bwdWindowSize=row['bwd window size'],

                protocol=row['protocol'],

                bwdVarianceDelta=row['bwd varianceDelta'],
                fwdVarianceDelta=row['fwd varianceDelta'],
                bwdMeanDelta=row['bwd meanDelta'],
                fwdMeanDelta=row['fwd meanDelta'],
                bwdStdDevDelta=row['bwd stdDevDelta'],
                fwdStdDevDelta=row['fwd stdDevDelta'],

                fwdPayloadVariance=row['fwd variancePayloadSize'],
                bwdPayloadVariance=row['bwd variancePayloadSize'],

                fwdPayloadSize=row['fwd payload size'],
                bwdPayloadSize=row['bwd payload size'],
                fwdPacketCount=row['fwd packetCount'],
                bwdPacketCount=row['bwd packetCount'],

                fwdFlowPacketRate=row['fwd Packet Flow Rate/s'],
                bwdFlowPacketRate=row['bwd Packet Flow Rate/s'],

                synFlag=row['SYN-Flag count'],
                ackFlag=row['ACK-Flag count'],
                rstFlag=row['RST-Flag count'],
                urgFlag=row['URG-Flag count'],
                pshFlag=row['PSH-Flag count'],
                eceFlag=row['ECE-Flag count'],
                cwrFlag=row['CWR-Flag count'],

                fwdUniquePorts=row['Unique Ports'],
                authFailures=row['Auth Failures'],

                FwdPacketByteRate=row['Fwd Packet Bytes/s'],
                BwdPacketByteRate=row['Bwd Packet Bytes/s'],

                packetCount=row['packetCount'],
                totalFwdByteCount=row['total fwd byteCount'],
                totalBwdByteCount=row['total bwd byteCount'],
                fwdFlowDuration=row['fwd flowDuration'],
                bwdFlowDuration=row['bwd flowDuration'],
                fwdMeanByteSize=row['fwd meanByteSize'],
                fwdStDevByteSize=row['fwd stDevByteSize'],
                fwdVarianceByteSize=row['fwd varianceByteSize'],
                bwdMeanByteSize=row['bwd meanByteSize'],
                bwdStDevByteSize=row['bwd stDevByteSize'],
                bwdVarianceByteSize=row['bwd varianceByteSize'],
                rtt=row['rtt'],
                Label=row['Label'])

        except (IntegrityError):
            print("Duplicate flow, skipping")
            continue

    print(len(Flow.objects.all()), 'flows inserted.')

    if (os.path.exists('model.tf')):
        startTestingThread(flowDataFrame)

    FlowExtractor(interface, capture, captureDuration, IP)
    return 0

def main(IP):
    captureDuration = 30
    #Flow.objects.all().delete()

    print("Flow extractor is running.")
    command = "grep 'client_ip=' /var/log/xrdp.log | tail -n1 | awk -F'client_ip=| client_port=' '{print $2}' | sed 's/::ffff://' | cut -d' ' -f1"
    ipAddress = subprocess.check_output(command, shell=True, text=True).strip()

    #XRDPCIDR = "78.17.0.0/24"
    DHCP = "255.255.255.255"
    if IP:
        filter = f"(src host {IP} or dst host {IP})"
        capture = pyshark.LiveCapture(interface='eth0', bpf_filter=filter)
    else:
        #filter = f"(not net {XRDPCIDR} and not dst host {DHCP})"
        #filter = f"(not dst host {DHCP})"
        #filter = f"not (net {ipAddress} and dst port 53579 or src port 53579)"
        filter = f"not net {ipAddress}"
        capture = pyshark.LiveCapture(interface='eth0', bpf_filter=filter)

    response = FlowExtractor('eth0', capture, captureDuration, IP)


if __name__ == "__main__":
    main()
