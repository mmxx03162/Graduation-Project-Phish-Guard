# api/serializers.py
# Serializers for the Phish-Guard API
# This module handles data serialization and validation for API requests and responses

from rest_framework import serializers
from .models import ScanResult

class ScanResultSerializer(serializers.ModelSerializer):
    """
    Serializer for ScanResult model.
    
    This serializer handles the conversion between ScanResult model instances
    and JSON data for API communication. It defines which fields are included
    in the serialized output and handles validation of incoming data.
    """
    
    class Meta:
        """
        Meta class defining serializer configuration.
        
        This class specifies the model to serialize and which fields
        should be included in the serialized output.
        """
        model = ScanResult
        fields = ['id', 'url', 'result', 'reason', 'timestamp']
        read_only_fields = ['result', 'reason', 'timestamp']
        