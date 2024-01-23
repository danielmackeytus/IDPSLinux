from django.contrib import admin
from django.urls import path, re_path
from IDPBackend import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/startCapture/', views.flow_list),
    path('api/startCapture/<str:IP>/', views.flow_list),
    path('api/TrafficStatus/', views.TrafficStatusView),
    path('api/StartTraining/', views.StartTraining),
    path('api/FetchAnomalousFlow/', views.fetchAnomalousFlow),
    path('api/DeleteFlowHistory/', views.ResetFlowHistory),
    path('api/MoveToTraining/', views.MoveToTraining),
    path('api/BanIP/', views.BanIP),
    path('api/UnbanIP/', views.UnbanIP),
    path('api/TrainingInfo/', views.TrainingInfo),
    re_path(r'^api/stopCapture/', views.stopSnifferCapture),
    re_path(r'^api/status/', views.SnifferStatus),
    
    path('api/register/', views.UserRegister, name='register'),
    path('api/login/', views.UserLogin, name='login'),
    path('api/logout/', views.UserLogout, name='logout'),
    path('api/user/', views.UserView, name='user'),
]
