from collections import Counter

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication
from rest_framework import status
from django.db.models import Avg, Count, Sum, Max, Min
import pandas as pd

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
from django.http import JsonResponse
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
    if request.method == 'GET':
        # LabelSumAgg = Flow.objects.aggregate(sum_label=Sum('Label',default=0))
        NewFlow = Flow.objects.exclude(srcIP='149.102.157.168')
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


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return 0


@api_view(['GET', 'POST'])
@authentication_classes([CsrfExemptSessionAuthentication])
def VulnerableView(request):
    if not request.user.is_authenticated:
        return Response({"status": "you need authorization"}, status=401)

    if request.method == 'GET':
        return Response({"status": "GET method executed."})
    elif request.method == 'POST':
        return Response({"status": "POST method executed."})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def MoveToTraining(request):
    print('request', request)
    if request.method == 'POST':
        try:
            #file = request.data.get('FlowIdentifier')
            label = request.data.get('ClassLabel')
            print('label:', label)

            flowData = pd.read_csv('FlowData.csv')
            flowData['Label'] = label

            path = ('TrainingData/' + label + '.csv')
            if os.path.exists(path):
                flowData.drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv(path, mode='a', header=False, index=False)
                os.remove('FlowData.csv')

            else:
                flowData.drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv('FlowData.csv', index=False)
                os.rename('FlowData.csv', path)

            return JsonResponse({'message': 'Flow moved'}, status=200);
        except(FileNotFoundError):
            return JsonResponse({'message': 'No flow to move'}, status=404);


def startTrainerThread(Layers, Epochs):
    thread = Thread(target=MachineLearningTraining, args=(Layers, Epochs))
    thread.start()


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
                    'maxAgeInDays': '7',
                    'verbose': 'no'
                }

                headers = {
                    'Accept': 'application/json',
                    'Key': 'e8b8ecbf17807437c193297b178d91f9a31906424f2bb41b44e856cd67044e94cc9e361a5cbb1257'
                }

                response = requests.request(method='GET', url=url, headers=headers, params=querystring)

                decodedResponse = json.loads(response.text)
                json.dumps(decodedResponse, sort_keys=True, indent=4)

                allCategories = []

                if decodedResponse['data']['abuseConfidenceScore'] >= 60:
                    if len(decodedResponse['data']['reports']) > 10:

                        reports = decodedResponse['data']['reports'][:25]
                        for report in reports:
                            allCategories.extend(report['categories'])

                        mostCommonCategory = Counter(allCategories).most_common(1)[0][0]
                        Label = ""

                        categoryString = categoryMap[mostCommonCategory]
                        Label = Label + categoryString
                        print(Label)

                        path = ('TrainingData/' + "AbuseIPDB - " + Label + '.csv')
                        if os.path.exists(path):
                            if Label != "Port Scan":
                                dataframe.at[index, 'Label'] = "AbuseIPDB - Suspicious"
                                dataframe.loc[[index]].drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv(path, mode='a',
                                                                                                              header=False,
                                                                                                          index=False)
                            else:
                                dataframe.at[index, 'Label'] = "AbuseIPDB - " + Label
                                dataframe.loc[[index]].drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv(path,
                                                                                                          mode='a',
                                                                                                          header=False,
                                                                                                          index=False)
                        else:
                            if Label != "Port Scan":
                                dataframe.at[index, 'Label'] = "AbuseIPDB - " + "Suspicious"
                                dataframe.loc[[index]].drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv(path, index=False)
                            else:
                                    dataframe.at[index, 'Label'] = "AbuseIPDB - " + Label
                                    dataframe.loc[[index]].drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv(path,
                                                                                                              mode='a',
                                                                                                              header=False,
                                                                                                              index=False)

                else:
                    dataframe.at[index, 'Label'] = "Normal"
                    print('IP is safe...')

                    path = ('TrainingData/' + "Normal" + '.csv')

                    if os.path.exists(path):
                        dataframe.loc[[index]].drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv(path, mode='a',
                                                                                                  header=False,
                                                                                                  index=False)
                        # os.remove('FlowData.csv')

                    else:
                        dataframe.loc[[index]].drop(['Origin', 'flowID', 'srcIP'], axis=1).to_csv(path, index=False)
                        # os.rename('FlowData.csv', path)
            except(KeyError):
                continue
        return JsonResponse({'message': '...'}, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def StartTraining(request):
    if not (os.listdir('TrainingData')):
        TrainingStatus.objects.create(status='No training files found.', previousTimestamp='unchanged');
        return JsonResponse({'status': 'No training files found.'});

    Layers = request.data.get('Layers')
    Epochs = request.data.get('Epochs')
    startTrainerThread(Layers, Epochs)

    TrainingStatus.objects.create(status='Training started.', previousTimestamp='today');

    return JsonResponse({'status': 'Training started.'});


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def BanIP(request):
    if request.method == "POST" and request.data.get('IPAddress') != "149.102.157.168":

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
        # queryset = AnomalousFlows = Flow.objects.all()
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
    # permissioncats = (permissions.AllowAny,)
    # authenticationcats = (SessionAuthentication,)

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
    # authenticationcats = (permissions.IsAuthenticated,)
    # permissioncats = (permissions.AllowAny,)

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
        queryset = TrainingStatus.objects.all()
        serializer = TrainingStatusSerializer(queryset, many=True)
        return Response(serializer.data);

    elif (request.method == 'POST'):
        serializer = TrainingStatusSerializer(data=request.data)

        if serializer.is_valid():
            TrainingStatus.objects.all().delete()
            serializer.save()
            return JsonResponse({"database": "instance created"});


def startSnifferThread(IP):
    thread = Thread(target=main, args=(IP,))
    thread.start()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def startSnifferCapture(request, IP=None):
    if request.method == 'POST':
        ip = request.GET.get('IP', '')
        print('ip: ', ip)
        # Flow.objects.all().delete()
        # FlowStatistics.objects.all().delete()
        startSnifferThread(IP)

        Task['sniffer'] = 'on'
        TrafficStatus.objects.create(status='scanning in progress')
        if (os.path.exists('model.tf')):
            return Response({"status": 'Sniffer started on a new thread.'})
        else:
            return Response({"status": 'No model found, sniffer started but will not make predictions.'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def stopSnifferCapture(request):
    Tasks = Task.get('sniffer')
    if Tasks == 'off':
        return JsonResponse({'status': 'Already stopped!'});

    Task['sniffer'] = 'off'

    return Response({'status': 'Sniffer thread will terminate shortly.'})


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
