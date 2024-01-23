from rest_framework.response import Response
from rest_framework import status
import pandas as pd
from rest_framework.decorators import api_view
from IDPBackend.models import Flow
from IDPBackend.serializers import FlowSerializer
from IDPBackend.serializers import SnifferStatusSerializer
from IDPBackend.serializers import TrafficStatusSerializer
from IDPBackend.serializers import TrainingStatusSerializer
from django.contrib.auth import get_user_model, login, logout
from rest_framework.authentication import SessionAuthentication
from IDPBackend.serializers import UserLoginSerializer, UserRegisterSerializer, UserSerializer
from django.views.decorators.csrf import csrf_exempt
from rest_framework import permissions, status
from rest_framework import viewsets
from asgiref.sync import async_to_sync
from IDPBackend.models import Status
from IDPBackend.models import TrafficStatus
from IDPBackend.models import TrainingStatus
from IDPBackend.FlowExtractor import main
from IDPBackend.MachineLearningTraining import MachineLearningTraining
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse
from .taskmanager import EventLoops
import iptc
import os
import asyncio

@api_view(['GET', 'POST'])
def flow_list(request,IP=None):

    if request.method == 'GET':
        ip = request.GET.get('IP','')
        print('ip: ',ip)
        #main runs indefinitely
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        EventLoops['sniffer'] = loop
        TrafficStatus.objects.create(status='scanning in progress')
        main(IP)
        return Response({"status": 'Sniffer returned for some reason.'})

        #serializer = FlowSerializer(flows, context={'request': request}, many=True)
        #return Response(serializer.data)
        
    elif request.method == 'POST':

        serializer = FlowSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def ResetFlowHistory(request):
   if request.method == 'DELETE':
      try:
         os.remove('FlowData.csv')
         return JsonResponse({'message':'Flow History Reset'}, status = 200);
      except(FileNotFoundError):
         return JsonResponse({'message':'No flow exists'}, status = 404);
         
@api_view(['POST'])
def MoveToTraining(request):
   print('request',request)
   if request.method == 'POST':
      try:
         file = request.data.get('FlowIdentifier')
         label = request.data.get('ClassLabel')
         print('label:',label)
         
         flowData = pd.read_csv('FlowData.csv')
         flowData['Label'] = label
         
         path = ('TrainingData/'+file+'.csv')
         if os.path.exists(path):
            flowData.drop(['flowID','srcIP'],axis=1).to_csv(path, mode='a', header=False, index=False)
            os.remove('FlowData.csv')
         
         else:
            flowData.drop(['flowID','srcIP'],axis=1).to_csv('FlowData.csv', index=False)   
            os.rename('FlowData.csv',path)
            
         return JsonResponse({'message':'Flow moved'}, status = 200);
      except(FileNotFoundError):
         return JsonResponse({'message':'No flow to move'}, status = 404);
         
@api_view(['POST'])
def StartTraining(request):

   loop = asyncio.new_event_loop()
   asyncio.set_event_loop(loop)
   EventLoops['trainer'] = loop
   EventLoopTrainer = EventLoops.get('trainer')
   Layers = request.data.get('Layers')
   MachineLearningTraining(Layers)
   TrainingStatus.objects.create(status='Training started.',previousTimestamp='today');
   
   
   return JsonResponse({'status': 'Training complete.'});

@api_view(['POST'])
def BanIP(request):
   if (request.method == "POST" and request.data.get('IPAddress') != "149.102.157.168"):

      table = iptc.Table(iptc.Table.FILTER)
      chain = iptc.Chain(table, "INPUT")
      
      for rule in chain.rules:
         if request.data.get('IPAddress') in rule.src:
            return JsonResponse({'status': 'IP is already banned.'});

      rule = iptc.Rule()
      rule.src = request.data.get('IPAddress')
      
      action = iptc.Target(rule,"DROP")
      rule.target = action
      
      chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
      chain.insert_rule(rule)
      
      return JsonResponse({'status': 'IP Banned.'});
   else:
      return JsonResponse({'status': 'You cant ban yourself.'});

@api_view(['POST'])
def UnbanIP(request):
   if (request.method == "POST"):
      
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
def fetchAnomalousFlow(request):
    if (request.method == 'GET'):
        queryset = AnomalousFlows = Flow.objects.all()
        serializer = FlowSerializer(queryset, many=True)
    return Response(serializer.data)

@api_view(['POST'])
def UserRegister(request):
   permissioncats = (permissions.AllowAny,)
   if (request.method == 'POST'):
      serializer = UserRegisterSerializer(data=request.data)
      if (serializer.is_valid()):
         user = serializer.create(request.data)
         if user:
            return Response(serializer.data, status=status.HTTP_201_CREATED)
      return Response(status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def UserLogin(request):
   permissioncats = (permissions.AllowAny,)
   authenticationcats = (SessionAuthentication,)
  
   if (request.method == 'POST'):
      serializer = UserLoginSerializer(data=request.data)
      if (serializer.is_valid()):
         user = serializer.checkIfExists(request.data)
         login(request,user)
         
         return Response({'state': serializer.data}, status=status.HTTP_200_OK)
      else:
        return Response({'state': 'user login serializer is not valid'})
       
      
@api_view(['POST'])
def UserLogout(request):
   if (request.method == 'POST'):
      logout(request)
      return Response(status=status.HTTP_200_OK)
   return Response(status=status.HTTP_400_BAD_REQUEST)
       
@api_view(['GET'])
def UserView(request):
        
   authenticationcats = (permissions.IsAuthenticated,)
   permissioncats = (permissions.AllowAny,)
   
   if (request.method == 'GET'):
      
      serializer = UserSerializer(request.user)
      
      return Response({'user': serializer.data}, status=status.HTTP_200_OK)


@api_view(['GET','POST'])
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
   else:
      return JsonResponse({"error": "who knows"});
      
@api_view(['GET', 'POST'])
def stopSnifferCapture(request):

   EventLoop = EventLoops.get('sniffer')
   if EventLoop is None:
        return JsonResponse({'status': 'Already stopped!'});
   else:
      for task in asyncio.all_tasks(EventLoop):
        task.cancel()
      
   Status.objects.create(status='Sniffer Off');
   if EventLoop.is_closed():
      print('Event loop successfully stopped')
   EventLoops['sniffer'] = None
   return JsonResponse({'status': 'Sniffer Off'});
   
@api_view(['GET', 'POST'])
def SnifferStatus(request):
   if request.method == 'GET':
   
      LatestStatus = Status.objects.last().status  
   
      EventLoop = EventLoops.get('sniffer')
      if EventLoop is None:
         LatestStatus = "Sniffer Off"

      serializer = SnifferStatusSerializer({'status': LatestStatus})

      return Response(serializer.data)


@api_view(['POST','GET'])
def TrafficStatusView(request):
   if request.method == 'POST':
        serializer = TrafficStatusSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
   
   
   elif request.method == 'GET':

      EventLoop = EventLoops.get('sniffer')
      LatestTrafficStatus = TrafficStatus.objects.last().status  
      if EventLoop is not None:
         serializer = TrafficStatusSerializer({'status': LatestTrafficStatus})
         return Response(serializer.data)
      else:
         return Response(status=status.HTTP_400_BAD_REQUEST)
