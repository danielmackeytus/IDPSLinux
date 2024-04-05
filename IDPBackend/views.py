from collections import Counter

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication
from rest_framework import status
from django.db.models import Avg, Count, Sum, Max, Min
import pandas as pd
import requests

from IDPBackend.models import Flow
from IDPBackend.serializers import FlowSerializer, FlowStatisticsSerializer, checkIfExists
from IDPBackend.models import FlowStatistics
from IDPBackend.serializers import SnifferStatusSerializer
from IDPBackend.serializers import TFMetricsSerializer
from IDPBackend.serializers import TrafficStatusSerializer
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from IDPBackend.serializers import TrainingStatusSerializer
from django.contrib.auth import login, logout
from IDPBackend.serializers import UserLoginSerializer, UserSerializer
from rest_framework import permissions, status
from IDPBackend.models import Status
from IDPBackend.models import TFMetrics
from IDPBackend.models import TrafficStatus
from IDPBackend.models import TrainingStatus
from IDPBackend.FlowExtractor import main
from IDPBackend.MachineLearningTraining import MachineLearningTraining
from django.http import JsonResponse, HttpResponse
from .taskmanager import Task
import iptc
import os
from threading import Thread


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def ResetFlowHistory(request):
    if request.method == 'DELETE':
        try:
            os.remove('FlowData.csv')
            return JsonResponse({'message': 'Flow History Reset'}, status=200);
        except FileNotFoundError:
            return JsonResponse({'message': 'No flow exists'}, status=404);


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def DeleteAllAnomalies(request):
    if request.method == 'DELETE':
        Flow.objects.all().delete()
        return JsonResponse({'message': 'Anomaly History Reset'}, status=200);


@api_view(['GET'])
def FetchFlowStatistics(request):
    response = requests.get('https://httpbin.org/ip')
    HostIP = response.json()

    if request.method == 'GET':
        NewFlow = Flow.objects.exclude(srcIP=HostIP.get('origin'))
        CountryFreqAgg = NewFlow.values('Origin').annotate(count=Count('id'))
        LabelFreqAgg = NewFlow.values('Label').annotate(count=Count('id'))
        srcIPs = NewFlow.values('srcIP').annotate(count=Count('id'))

        listData = list(LabelFreqAgg)
        listData2 = list(CountryFreqAgg)
        listData3 = list(srcIPs)

        FlowStatisticsInstance = FlowStatistics.objects.create(FrequentAttack=listData,
                                                               FrequentOrigin=listData2,
                                                               srcIP=listData3)

        FlowStatisticsInstance.save()

        serializer = FlowStatisticsSerializer(FlowStatisticsInstance, many=False)
        return Response(serializer.data)


@api_view(['POST'])
def IgnoreIP(request):
    if request.method == 'POST':
        Flow.objects.filter(srcIP=request.data.get('IPAddress')).delete()
        FlowStatistics.objects.filter(srcIP=request.data.get('IPAddress')).delete()
        Flow.save()
        FlowStatistics.save()
        return JsonResponse({'status': 'IP Ignored'})


# class CsrfExemptSessionAuthentication(SessionAuthentication):
#    def enforce_csrf(self, request):
#        return 0


# @api_view(['GET', 'POST'])
# @authentication_classes([CsrfExemptSessionAuthentication])
# def VulnerableView(request):
#    if not request.user.is_authenticated:
#        return Response({"status": "you need authorization"}, status=401)#
#
#   if request.method == 'GET':
#        return Response({"status": "GET method executed."})
#    elif request.method == 'POST':
#        return Response({"status": "POST method executed."})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def MoveToTraining(request):
    print('request', request)
    if request.method == 'POST':
        try:
            label = request.data.get('ClassLabel')
            print('label:', label)

            flowData = pd.read_csv('FlowData.csv')
            flowData['Label'] = label

            path = ('TrainingData/' + label + '.csv')
            if os.path.exists(path):
                flowData.drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv(path, mode='a', header=False, index=False)
                os.remove('FlowData.csv')

            else:
                flowData.drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv('FlowData.csv', index=False)
                os.rename('FlowData.csv', path)

            return JsonResponse({'message': 'Flow moved'}, status=200);
        except(FileNotFoundError):
            return JsonResponse({'message': 'No flow to move'}, status=404);


def startTrainerThread(Layers, Epochs):
    thread = Thread(target=MachineLearningTraining, args=(Layers, Epochs))
    thread.start()


@api_view(['GET','POST'])
def FetchHostIP(request):
    if request.method == 'GET' or request.method == 'POST':
        try:
            response = requests.get('https://httpbin.org/ip')
            if response.status_code == 200:
                ip_data = response.json()
                public_ip = ip_data.get('origin')
                return Response(public_ip)
            else:
                print(f"Failed to retrieve IP (Status code: {response.status_code})")
        except Exception as e:
            print(f"Error: {e}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def AbuseIPDB(request):
    if request.method == 'GET':
        import requests
        import json

        categoryMap = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted",
        }

        dataframe = pd.read_csv('FlowData.csv', sep=r'\s*,\s*', engine='python')
        url = 'https://api.abuseipdb.com/api/v2/check'

        for index, row in dataframe.iterrows():
            try:
                IP = row["srcIP"]

                querystring = {
                    'ipAddress': IP,
                    'maxAgeInDays': '14',
                    'verbose': 'no'
                }

                headers = {
                    'Accept': 'application/json',
                    'Key': 'c7318b06712c621622ea876d243eb422be34a1eceea733571eb0d7b92cae1fd0e34cf9499430ad3b'
                }

                response = requests.request(method='GET', url=url, headers=headers, params=querystring)

                decodedResponse = json.loads(response.text)
                json.dumps(decodedResponse, sort_keys=True, indent=4)

                allCategories = []

                if (decodedResponse['data']['abuseConfidenceScore'] > 0 and
                        len(decodedResponse['data']['reports']) > 10):
                    print('ip: ' + IP + ' is abusive.')
                    reports = decodedResponse['data']['reports'][:25]
                    for report in reports:
                        allCategories.extend(report['categories'])

                    mostCommonCategory = Counter(allCategories).most_common(1)[0][0]
                    Label = ""

                    categoryString = categoryMap[mostCommonCategory]
                    Label = Label + categoryString
                    print(Label)

                    path = ('TrainingData/' + "AbuseIPDB - " + Label + '.csv')
                    extraPath = 'Extra/' + Label + '.csv'

                    if os.path.exists(extraPath) or os.path.exists(path):

                        if Label != "Port Scan":

                            dataframe.at[index, 'Label'] = "AbuseIPDB - " + Label
                            dataframe.loc[[index]].drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv(
                                extraPath, mode='a', header=False, index=False)

                        elif os.path.exists(path):
                            dataframe.at[index, 'Label'] = "AbuseIPDB - " + Label
                            dataframe.loc[[index]].drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv(path,
                                                                                                       mode='a',
                                                                                                       index=False,
                                                                                                       header=False)
                    else:
                        if Label != "Port Scan":
                            dataframe.at[index, 'Label'] = "AbuseIPDB - " + Label
                            dataframe.loc[[index]].drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv(
                                extraPath, index=False)
                        else:
                            dataframe.at[index, 'Label'] = "AbuseIPDB - " + Label
                            dataframe.loc[[index]].drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv(path,
                                                                                                       index=False)

                elif (decodedResponse['data']['abuseConfidenceScore'] == 0 or
                      len(decodedResponse['data']['reports']) < 10):
                    print('ip: ' + IP + ' is NOT abusive.')
                    dataframe.at[index, 'Label'] = "Normal"

                    path = ('TrainingData/' + "Normal" + '.csv')

                    if os.path.exists(path):
                        dataframe.loc[[index]].drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv(path, mode='a',
                                                                                                   header=False,
                                                                                                   index=False)


                    else:
                        dataframe.loc[[index]].drop(['Origin', 'forward', 'srcIP'], axis=1).to_csv(path, index=False)
            except KeyError:
                continue
            os.remove('FlowData.csv')
        return JsonResponse({'message': '...'}, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def StartTraining(request):
    try:
        if not (os.listdir('TrainingData')):
            TrainingStatus.objects.create(status='No training files found.', previousTimestamp='unchanged');
            return JsonResponse({'status': 'No training files found.'});

        Layers = request.data.get('Layers')
        Epochs = request.data.get('Epochs')
        startTrainerThread(Layers, Epochs)

    except(ValueError):
        return JsonResponse({'status': 'Invalid inputs.'});
    return JsonResponse({'status': 'Training started.'});


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def BanIP(request):

    print(request.data.get('PublicIP'))

    if request.method == "POST" and request.data.get('IPAddress') != request.data.get('PublicIP'):

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")

        for rule in chain.rules:
            if request.data.get('IPAddress') in rule.src:
                return JsonResponse({'status': 'IP is already banned.'});

        rule = iptc.Rule()
        rule.src = request.data.get('IPAddress')

        action = iptc.Target(rule, "DROP")
        rule.target = action

        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.insert_rule(rule)

        return JsonResponse({'status': 'IP Banned.'});
    else:
        return JsonResponse({'status': 'You cant ban yourself.'});


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def UnbanIP(request):
    if request.method == "POST":

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")

        for rule in chain.rules:
            if request.data.get('IPAddress') in rule.src:
                chain.delete_rule(rule)
                print("IP Unbanned")
                return JsonResponse({'status': 'IP Unbanned.'});

        return JsonResponse({'status': 'IP is not banned'});
    else:
        return JsonResponse({'status': 'Something went wrong.'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def fetchAnomalousFlow(request):
    if request.method == 'GET':
        queryset = Flow.objects.all()
        serializer = FlowSerializer(queryset, many=True)
    return Response(serializer.data)


# api_view(['POST'])
# def UserRegister(request):
# permissioncats = (permissions.AllowAny,)
# if request.method == 'POST':
# serializer = UserRegisterSerializer(data=request.data)
# if (serializer.is_valid()):
# user = serializer.create(request.data)
# if user:
# return Response(serializer.data, status=status.HTTP_201_CREATED)
# return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def UserLogin(request):
    if request.method == 'POST':
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = checkIfExists(request.data)
            login(request, user)

            return Response({'state': serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({'state': 'user login serializer is not valid'})


@permission_classes([IsAuthenticated])
@api_view(['POST'])
def UserLogout(request):
    if (request.method == 'POST'):
        logout(request)
        return Response(status=status.HTTP_200_OK)
    return Response(status=status.HTTP_400_BAD_REQUEST)


@permission_classes([IsAuthenticated])
@api_view(['GET'])
def UserView(request):
    if (request.method == 'GET'):

        if request.user.is_authenticated:
            serializer = UserSerializer(request.user)

            return Response({'user': serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'nobody is logged in'})


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def TrainingInfo(request):
    if (request.method == 'GET'):
        query = TrainingStatus.objects.last().previousTimestamp
        serializer = TrainingStatusSerializer({'previousTimestamp': query})
        return Response(serializer.data)

    elif (request.method == 'POST'):
        serializer = TrainingStatusSerializer(data=request.data)

        if serializer.is_valid():
            TrainingStatus.objects.create(previousTimestamp=request.data.get('previousTimestamp'))
            serializer.save()
        return JsonResponse({"previousTimestamp": request.data.get('previousTimestamp')});


def startSnifferThread(IP):
    thread = Thread(target=main, args=(IP,))
    thread.start()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def startSnifferCapture(request, IP=None):
    if request.method == 'POST':

        startSnifferThread(IP)

        Task['sniffer'] = 'on'
        TrafficStatus.objects.create(status='scanning in progress')

        if (os.path.exists('model.tf')):
            return Response({"status": 'Sniffer started.'})
        else:
            TrafficStatus.objects.create(status='scanning in progress, predictions disabled.')
            return Response({"status": 'No model found, sniffer started but will not make predictions.'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def stopSnifferCapture(request):
    Tasks = Task.get('sniffer')
    if Tasks == 'off':
        return JsonResponse({'status': 'Already stopped!'});

    Task['sniffer'] = 'off'

    return Response({'status': 'Sniffer will terminate shortly.'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def SnifferStatus(request):
    if request.method == 'GET':

        LatestStatus = Status.objects.last().status

        Tasks = Task.get('sniffer')
        if Tasks is None:
            LatestStatus = "Sniffer Off"

        serializer = SnifferStatusSerializer({'status': LatestStatus})

        return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def TFPerformanceMetrics(request):
    if request.method == 'GET':
        accuracy = TFMetrics.objects.last().accuracy
        accuracy_loss = TFMetrics.objects.last().loss
        validation_accuracy = TFMetrics.objects.last().val_accuracy
        validation_loss = TFMetrics.objects.last().val_loss

        serializer = TFMetricsSerializer({'accuracy': accuracy,
                                          'loss': accuracy_loss,
                                          'val_accuracy': validation_accuracy,
                                          'val_loss': validation_loss})

        return Response(serializer.data)


@permission_classes([IsAuthenticated])
@api_view(['GET', 'POST'])
def TrafficStatusView(request):
    if request.method == 'POST':
        serializer = TrafficStatusSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':

        Tasks = Task.get('sniffer')
        LatestTrafficStatus = TrafficStatus.objects.last().status
        if Tasks is not None:
            serializer = TrafficStatusSerializer({'status': LatestTrafficStatus})
            return Response(serializer.data)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
