from django.db import models
from django.core import serializers
from django.utils import timezone
import uuid

# Create your models here.
class Session(models.Model):
    timestamp = models.DateTimeField(auto_now=True)
    token = models.BinaryField()

class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(null=True)
    name = models.CharField(max_length=128)
    username = models.CharField(max_length=64, null=True)
    secret = models.BinaryField(null=True)
    verified = models.FloatField(default=0)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
