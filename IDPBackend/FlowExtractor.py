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

    try:
        Status.objects.create(status='Sniffer On')
        for packet in capture.sniff_continuously():
            currentTime = time.time()

            if currentTime - startTime >= captureDuration:
                break

            flag = ''
            window = 0
            payloadSize = 0
            timeDelta = 0

            if 'ip' in packet and packet is not None:

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

                key = srcIP + dstIP
                fwdUniquePorts.setdefault(key, [])

                if dstPort not in fwdUniquePorts.get(key, []):
                    fwdUniquePorts[key].append(dstPort)

                elapsedTime = 0

                forward = "{} {} {} {} {}".format(srcIP, srcPort, dstIP, dstPort, protocol)
                backward = "{} {} {} {} {}".format(dstIP, dstPort, srcIP, srcPort, protocol)

                if forward not in flows and backward not in flows:
                    flows[forward] = {

                        'forward': forward,
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
                        'SYN': 0.0,

                        'Forward FIN flag count': 0.0,
                        'Forward SYN flag count': 0.0,
                        'Forward RST flag count': 0.0,
                        'Forward ACK flag count': 0.0,
                        'Forward 0x0014 flag count': 0.0,
                        'Forward ACK-PSH flag count': 0.0,
                        'Forward 0x003F flag count': 0.0,
                        'Forward ACK-FIN-PSH flag count': 0.0,
                        'Forward URG flag count': 0.0,
                        'Forward FIN-ACK flag count': 0.0,

                        'Backward FIN flag count': 0.0,
                        'Backward RST flag count': 0.0,
                        'Backward ACK flag count': 0.0,
                        'Backward 0x0014 flag count': 0.0,
                        'Backward ACK-PSH flag count': 0.0,
                        'Backward 0x003F flag count': 0.0,
                        'Backward SYN-ACK flag count': 0.0,
                        'Backward ACK-FIN-PSH flag count': 0.0,
                        'Backward URG flag count': 0.0,
                        'Backward FIN-ACK flag count': 0.0,

                        'Label': 0,

                    }

                fwdByteCountList.setdefault(forward, [])
                bwdByteCountList.setdefault(backward, [])

                fwdDelta.setdefault(forward, [])
                bwdDelta.setdefault(backward, [])

                fwdPayloadSizes.setdefault(forward, [])
                bwdPayloadSizes.setdefault(backward, [])

                if 'TCP' in packet:
                    tcpPacket = packet.tcp

                    window = tcpPacket.window_size
                    timeDelta = tcpPacket.time_delta

                    fwdDelta[forward].append(float(timeDelta))

                    if hasattr(tcpPacket, 'payload'):
                        payloadSize = len(bytearray.fromhex(tcpPacket.payload.replace(':', '')))

                    tcpStream = packet.tcp.stream
                    packetTimestamp = float(packet.sniff_timestamp)
                    flag = packet.tcp.flags

                    if tcpStream not in streams:
                        streams[tcpStream] = {'PTS': packetTimestamp, 'SYN': False, 'SYN-ACK': False,
                                              'RTT-CHECK': False}

                        if flag == '0x0002':
                            flows[forward]['Forward SYN flag count'] += 1

                            print('SYN flag belonging to', forward)
                            streams[tcpStream]['synTime'] = float(packet.sniff_timestamp)
                            streams[tcpStream]['SYN'] = True
                    # else:
                    if flag == '0x0012':
                        print('SYN-ACK flag belonging to', backward)
                        streams[tcpStream]['syn-ackTime'] = float(packet.sniff_timestamp)
                        streams[tcpStream]['SYN-ACK'] = True

                    elapsedTime = packetTimestamp - streams[tcpStream]['PTS']

                if forward in flows:
                    if flag == '0x0001':
                        flows[forward]['Forward FIN flag count'] += 1
                    if flag == '0x0002':
                        flows[forward]['Forward SYN flag count'] += 1
                    if flag == '0x0004':
                        flows[forward]['Forward RST flag count'] += 1
                    if flag == '0x0010':
                        flows[forward]['Forward ACK flag count'] += 1
                    if flag == '0x0014':
                        flows[forward]['Forward 0x0014 flag count'] += 1
                    if flag == '0x0018':
                        flows[forward]['Forward ACK-PSH flag count'] += 1
                    if flag == '0x003F':
                        flows[forward]['Forward 0x003F flag count'] += 1
                    if flag == '0x0019':
                        flows[forward]['Forward ACK-FIN-PSH flag count'] += 1
                    if flag == '0x0020':
                        flows[forward]['Forward URG flag count'] += 1
                    if flag == '0x0011':
                        flows[forward]['Forward FIN-ACK flag count'] += 1

                    flows[forward]['fwd time delta'] = float(timeDelta)

                    fwdDelta[forward].append(float(timeDelta))

                    flows[forward]['Unique Ports'] = len(fwdUniquePorts[key])

                    if os.path.getsize(logFilePath) != 0:
                        # print("auth.log exists.")

                        result = subprocess.run(["grep", "-c", "Failed password", logFilePath], capture_output=True,
                                                text=True)
                        count = int(result.stdout.strip())
                        # print(f"Authentication failure count: {count}")
                        flows[forward]['Auth Failures'] = count
                    if 'UDP' not in packet:

                        flows[forward]['fwd flags'] = flag
                        flows[forward]['fwd payload size'] += payloadSize
                        fwdPayloadSizes[forward].append(payloadSize)
                        flows[forward]['fwd window size'] = window

                        if streams[tcpStream]['SYN'] == True and streams[tcpStream]['SYN-ACK'] == True and \
                                streams[tcpStream]['RTT-CHECK'] == False:
                            RTT = streams[tcpStream]['syn-ackTime'] - streams[tcpStream]['synTime']
                            flows[forward]['rtt'] = RTT
                            streams[tcpStream]['RTT-CHECK'] = True

                    # get statistics for udp also

                    if int(packet.length) < flows[forward]['min fwd packet length']:
                        flows[forward]['min fwd packet length'] = int(packet.length)
                    if int(packet.length) > flows[forward]['max fwd packet length']:
                        flows[forward]['max fwd packet length'] = int(packet.length)

                    flows[forward]['fwd flowDuration'] += elapsedTime
                    flows[forward]['packetCount'] += 1

                    flows[forward]['fwd packetCount'] += 1
                    flows[forward]['total fwd byteCount'] += int(packet.length)

                    totalFwdByteCount = flows[forward]['total fwd byteCount']
                    totalFwdDuration = flows[forward]['fwd flowDuration']
                    if (totalFwdDuration != 0):
                        fwdByteCountList[forward].append(int(packet.length))
                        flows[forward]['Fwd Packet Bytes/s'] = totalFwdByteCount / totalFwdDuration

                    if (flows[forward]['fwd flowDuration'] != 0):
                        flows[forward]['fwd meanByteSize'] = flows[forward]['total fwd byteCount'] / flows[forward][
                            'fwd packetCount']
                        flows[forward]['fwd Packet Flow Rate/s'] = flows[forward]['fwd packetCount'] / flows[forward][
                            'fwd flowDuration']

                    if (len(fwdByteCountList[forward]) >= 2):
                        flows[forward]['fwd stDevByteSize'] = statistics.stdev(fwdByteCountList[forward])
                        flows[forward]['fwd varianceByteSize'] = statistics.variance(fwdByteCountList[forward])

                        if (len(fwdPayloadSizes[forward]) >= 2):
                            flows[forward]['fwd variancePayloadSize'] = statistics.variance(fwdPayloadSizes[forward])

                        flows[forward]['fwd stdDevDelta'] = np.std(fwdDelta[forward])
                        flows[forward]['fwd varianceDelta'] = statistics.variance(fwdDelta[forward])
                        flows[forward]['fwd meanDelta'] = statistics.mean(fwdDelta[forward])

                    elif 'UDP' in packet:
                        flows[forward]['Unique Ports'] = len(fwdUniquePorts[key])

                        UDPHeaderLength = 8
                        UDPPayloadSize = int(packet.udp.length) - UDPHeaderLength
                        flows[forward]['fwd payload size'] += UDPPayloadSize

                elif backward in flows:

                    flows[backward]['bwd time delta'] = float(timeDelta)
                    bwdDelta[backward].append(float(timeDelta))

                    if 'UDP' not in packet:
                        flows[backward]['bwd flags'] = flag

                        if flag == '0x0001':
                            flows[backward]['Backward FIN flag count'] += 1
                        if flag == '0x0002':
                            flows[backward]['Backward SYN flag count'] += 1
                        if flag == '0x0004':
                            flows[backward]['Backward RST flag count'] += 1
                        if flag == '0x0010':
                            flows[backward]['Backward ACK flag count'] += 1
                        if flag == '0x0018':
                            flows[backward]['Backward ACK-PSH flag count'] += 1
                        if flag == '0x003F':
                            flows[backward]['Backward 0x003F flag count'] += 1
                        if flag == '0x0012':
                            flows[backward]['Backward SYN-ACK flag count'] += 1
                        if flag == '0x0019':
                            flows[backward]['Backward ACK-FIN-PSH flag count'] += 1
                        if flag == '0x0014':
                            flows[backward]['Backward 0x0014 flag count'] += 1
                        if flag == '0x0020':
                            flows[backward]['Backward URG flag count'] += 1
                        if flag == '0x0011':
                            flows[backward]['Backward FIN-ACK flag count'] += 1

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

            try:
                check = flowDataFrame[['forward', 'Auth Failures', 'Unique Ports', 'Origin']]
            except(KeyError):
                print("Missing columns")
                FlowExtractor('eth0', capture, captureDuration, IP)

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
                forward=row['forward'],
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

                ForwardFinFlag=row['Forward FIN flag count'],
                ForwardSynFlag=row['Forward SYN flag count'],
                ForwardRstFlag=row['Forward RST flag count'],
                ForwardAckFlag=row['Forward ACK flag count'],
                Forward0x0014Flag=row['Forward 0x0014 flag count'],
                ForwardAckPshFlag=row['Forward ACK-PSH flag count'],
                Forward0x003FFlag=row['Forward 0x003F flag count'],
                ForwardAckFinPshFlag=row['Forward ACK-FIN-PSH flag count'],
                ForwardUrgFlag=row['Forward URG flag count'],
                ForwardFinAckFlag=row['Forward FIN-ACK flag count'],

                BackwardFinFlag=row['Backward FIN flag count'],
                BackwardRstFlag=row['Backward RST flag count'],
                BackwardAckFlag=row['Backward ACK flag count'],
                Backward0x0014Flag=row['Backward 0x0014 flag count'],
                BackwardAckPshFlag=row['Backward ACK-PSH flag count'],
                Backward0x003FFlag=row['Backward 0x003F flag count'],
                BackwardSynAckFlag=row['Backward SYN-ACK flag count'],
                BackwardAckFinPshFlag=row['Backward ACK-FIN-PSH flag count'],
                BackwardUrgFlag=row['Backward URG flag count'],
                BackwardFinAckFlag=row['Backward FIN-ACK flag count'],

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
            print('duplicated flow:: ', row['forward'])
            print("Duplicate flow, skipping")
            continue

    print(len(Flow.objects.all()), 'flows inserted.')

    if (os.path.exists('model.tf')):
        startTestingThread(flowDataFrame)

    FlowExtractor(interface, capture, captureDuration, IP)
    return 0


def main(IP):
    captureDuration = 30

    print("Flow extractor is running.")
    command = "grep 'client_ip=' /var/log/xrdp.log | tail -n1 | awk -F'client_ip=| client_port=' '{print $2}' | sed 's/::ffff://' | cut -d' ' -f1"
    ipAddress = subprocess.check_output(command, shell=True, text=True).strip()

    if IP:
        filter = f"(src host {IP} or dst host {IP})"
        capture = pyshark.LiveCapture(interface='eth0', bpf_filter=filter)
    else:
        filter = f"not net {ipAddress}"
        capture = pyshark.LiveCapture(interface='eth0', bpf_filter=filter)

    response = FlowExtractor('eth0', capture, captureDuration, IP)


if __name__ == "__main__":
    main()
