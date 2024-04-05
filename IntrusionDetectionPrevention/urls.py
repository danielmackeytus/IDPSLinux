from django.contrib import admin
from django.urls import path, re_path
from IDPBackend import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/startCapture//', views.startSnifferCapture),
    path('api/startCapture/<str:IP>/', views.startSnifferCapture),
    path('api/TrafficStatus/', views.TrafficStatusView),
    path('api/StartTraining/', views.StartTraining),
    path('api/FetchAnomalousFlow/', views.fetchAnomalousFlow),
    path('api/DeleteFlowHistory/', views.ResetFlowHistory),
    path('api/FetchHostIP/', views.FetchHostIP),
    path('api/IgnoreIP/', views.IgnoreIP),
    path('api/MoveToTraining/', views.MoveToTraining),
    path('api/FetchFlowStatistics/', views.FetchFlowStatistics),
    path('api/banIP/', views.BanIP),
    #path('api/vulnerable/', views.VulnerableView),
    path('api/AbuseIPDB/', views.AbuseIPDB),
    path('api/unbanIP/', views.UnbanIP),
    path('api/DeleteAllAnomalies/', views.DeleteAllAnomalies),
    path('api/TrainingInfo/', views.TrainingInfo),
    path('api/MetricInfo/', views.TFPerformanceMetrics),
    re_path(r'^api/stopCapture/', views.stopSnifferCapture),
    re_path(r'^api/status/', views.SnifferStatus),
    #path('api/register/', views.UserRegister, name='register'),
    path('api/login/', views.UserLogin, name='login'),
    path('api/logout/', views.UserLogout, name='logout'),
    path('api/user/', views.UserView, name='user'),
]
