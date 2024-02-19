from rest_framework import serializers
from .models import Flow
from .models import Status
from .models import TrafficStatus
from .models import TrainingStatus
from .models import FlowStatistics
from django.contrib.auth import get_user_model, authenticate
from django.core.exceptions import ValidationError

UserModel = get_user_model()


class FlowSerializer(serializers.ModelSerializer):
    class Meta:
        model = Flow
        fields = ('__all__')


class FlowStatisticsSerializer(serializers.ModelSerializer):
    class Meta:
        model = FlowStatistics
        fields = ('__all__')


class SnifferStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Status
        fields = ['status']


class TrafficStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrafficStatus
        fields = ['status']


class TrainingStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrainingStatus
        fields = '__all__'


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = '__all__'

    def create(self, data):
        user = UserModel.objects.create_user(email=data['email'],
                                             password=data['password'])
        user.username = data['username']
        user.save()

        return user


def checkIfExists(data):
    user = authenticate(username=data['email'], password=data['password'])
    if not user:
        raise ValidationError("user not found")
    return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ('email', 'username', 'groups')
