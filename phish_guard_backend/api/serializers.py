# api/serializers.py

from rest_framework import serializers
from .models import ScanResult

class ScanResultSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = ScanResult
        fields = ['id', 'url', 'result', 'timestamp']