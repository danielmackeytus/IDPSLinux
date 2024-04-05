from django.db import models
from django.db.models import JSONField
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin


class Status(models.Model):
    status = models.CharField(max_length=20)

    def _str_(self):
        return f"{self.status}"


class TrafficStatus(models.Model):
    status = models.CharField(max_length=35)

    def _str_(self):
        return f"{self.status}"

class TFMetrics(models.Model):
    accuracy = models.CharField(max_length=35)
    loss = models.CharField(max_length=35)
    val_accuracy = models.CharField(max_length=35)
    val_loss = models.CharField(max_length=35)

    def _str_(self):
        return f"{self.accuracy}"

class TrainingStatus(models.Model):
    previousTimestamp = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.previousTimestamp}"


class FlowStatistics(models.Model):
    FrequentAttack = JSONField()
    FrequentOrigin = JSONField()
    srcIP = JSONField()

    def _str_(self):
        return f"{self.FrequentAttack}"


class Flow(models.Model):
    forward = models.CharField(max_length=50, unique=True)
    srcIP = models.CharField(max_length=20)
    dstPort = models.CharField(max_length=50)

    fwdFlags = models.CharField(max_length=25)
    bwdFlags = models.CharField(max_length=25)
    authFailures = models.CharField(max_length=5)

    Origin = models.CharField(max_length=25)

    fwdTimeDelta = models.CharField(max_length=15)
    bwdTimeDelta = models.CharField(max_length=15)

    fwdWindowSize = models.CharField(max_length=25)
    bwdWindowSize = models.CharField(max_length=25)

    protocol = models.CharField(max_length=10)

    fwdMeanDelta = models.CharField(max_length=25)
    bwdMeanDelta = models.CharField(max_length=25)
    fwdVarianceDelta = models.CharField(max_length=25)
    bwdVarianceDelta = models.CharField(max_length=25)
    fwdStdDevDelta = models.CharField(max_length=25)
    bwdStdDevDelta = models.CharField(max_length=25)

    ForwardFinFlag = models.CharField(max_length=25)
    ForwardSynFlag = models.CharField(max_length=25)
    ForwardRstFlag = models.CharField(max_length=25)
    ForwardAckFlag = models.CharField(max_length=25)
    Forward0x0014Flag = models.CharField(max_length=25)
    ForwardAckPshFlag = models.CharField(max_length=25)
    Forward0x003FFlag = models.CharField(max_length=25)
    ForwardAckFinPshFlag = models.CharField(max_length=25)
    ForwardUrgFlag = models.CharField(max_length=25)
    ForwardFinAckFlag = models.CharField(max_length=25)

    BackwardFinFlag = models.CharField(max_length=25)
    BackwardRstFlag = models.CharField(max_length=25)
    BackwardAckFlag = models.CharField(max_length=25)
    Backward0x0014Flag = models.CharField(max_length=25)
    BackwardAckPshFlag = models.CharField(max_length=25)
    Backward0x003FFlag = models.CharField(max_length=25)
    BackwardSynAckFlag = models.CharField(max_length=25)
    BackwardAckFinPshFlag = models.CharField(max_length=25)
    BackwardUrgFlag = models.CharField(max_length=25)
    BackwardFinAckFlag = models.CharField(max_length=25)

    FwdPacketByteRate = models.CharField(max_length=25)
    BwdPacketByteRate = models.CharField(max_length=25)

    fwdPayloadSize = models.CharField(max_length=25)
    bwdPayloadSize = models.CharField(max_length=25)

    fwdFlowPacketRate = models.CharField(max_length=25, default=1)
    bwdFlowPacketRate = models.CharField(max_length=25, default=1)

    fwdPayloadVariance = models.CharField(max_length=25)
    bwdPayloadVariance = models.CharField(max_length=25)

    fwdPacketCount = models.CharField(max_length=50)
    bwdPacketCount = models.CharField(max_length=50)
    packetCount = models.CharField(max_length=50)
    totalFwdByteCount = models.CharField(max_length=50)
    totalBwdByteCount = models.CharField(max_length=50)

    fwdFlowDuration = models.CharField(max_length=50)
    bwdFlowDuration = models.CharField(max_length=50)

    fwdUniquePorts = models.CharField(max_length=10)

    fwdMeanByteSize = models.CharField(max_length=50)
    bwdMeanByteSize = models.CharField(max_length=50)
    fwdStDevByteSize = models.CharField(max_length=50)
    bwdStDevByteSize = models.CharField(max_length=50)
    fwdVarianceByteSize = models.CharField(max_length=50)
    bwdVarianceByteSize = models.CharField(max_length=50)

    rtt = models.CharField(max_length=15)
    Label = models.CharField(max_length=15)


class AppUserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise ValueError('An email is required.')
        if not password:
            raise ValueError('A password is required.')
        email = self.normalize_email(email)
        user = self.model(email=email)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None):
        if not email:
            raise ValueError('An email is required.')
        if not password:
            raise ValueError('A password is required.')
        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class AppUser(AbstractBaseUser, PermissionsMixin):
    user_id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=50, unique=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = AppUserManager()

    def __str__(self):
        return self.email
