# api/views.py - Enhanced version with comprehensive English comments
# API views for the Phish-Guard phishing detection system
# This module handles HTTP requests and responses for URL scanning and data retrieval

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import SearchFilter, OrderingFilter
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from .models import ScanResult
from .serializers import ScanResultSerializer
from .predictor import make_prediction, get_models_status
import logging
import time

# Optional import for django_filters
try:
    from django_filters.rest_framework import DjangoFilterBackend
    DJANGO_FILTERS_AVAILABLE = True
except ImportError:
    DJANGO_FILTERS_AVAILABLE = False
    DjangoFilterBackend = None

# Configure logging for the application
logger = logging.getLogger(__name__)

def add_cors_headers(response):
    """
    Add CORS (Cross-Origin Resource Sharing) headers to the response.
    
    This function enables cross-origin requests from web browsers,
    allowing the frontend to communicate with the backend API.
    
    Args:
        response: The HTTP response object to modify
        
    Returns:
        Response: The response with CORS headers added
    """
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response['Access-Control-Allow-Credentials'] = 'true'
    return response

@csrf_exempt
@api_view(['POST'])
def scan_url_view(request):
    """
    API endpoint for scanning URLs and determining if they are phishing or legitimate.
    
    This view receives a URL in the request body, processes it through the
    machine learning models, and returns the classification result along with
    metadata about the scan.
    
    Args:
        request: HTTP request object containing the URL to scan
        
    Returns:
        Response: JSON response with scan results and metadata
    """
    start_time = time.time()
    
    try:
        # Validate the incoming request data
        serializer = ScanResultSerializer(data=request.data)
        
        if serializer.is_valid():
            # Extract the URL from the validated data
            url_to_check = serializer.validated_data['url']
            logger.info(f"Analyzing URL: {url_to_check}")
            
            # Make prediction using the machine learning models
            prediction_result = make_prediction(url_to_check)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Save the result to the database
            scan_result = serializer.save(result=prediction_result)
            
            # Prepare the response data
            response_data = {
                'id': scan_result.id,
                'url': scan_result.url,
                'result': scan_result.result,
                'timestamp': scan_result.timestamp,
                'processing_time': round(processing_time, 3),
                'status': 'success'
            }
            
            logger.info(f"Prediction completed: {prediction_result} (Time: {processing_time:.3f}s)")
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        else:
            logger.warning(f"Invalid request data: {serializer.errors}")
            return Response({
                'status': 'error',
                'message': 'Invalid request data',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(['GET'])
def models_status_view(request):
    """
    API endpoint for displaying the status of machine learning models.
    
    This view provides information about which models are loaded and ready
    for making predictions, helping with system monitoring and debugging.
    
    Args:
        request: HTTP request object
        
    Returns:
        Response: JSON response with model status information
    """
    try:
        models_status = get_models_status()
        loaded_count = sum(models_status.values())
        total_count = len(models_status)
        
        return Response({
            'status': 'success',
            'models_loaded': f"{loaded_count}/{total_count}",
            'models_status': models_status,
            'all_models_ready': loaded_count == total_count
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error getting models status: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Unable to get models status',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(['GET'])
def health_check_view(request):
    """
    API endpoint for system health verification.
    
    This endpoint provides basic information about the system status,
    available API endpoints, and service configuration.
    
    Args:
        request: HTTP request object
        
    Returns:
        Response: JSON response with system health information
    """
    return Response({
        'status': 'healthy',
        'service': 'Phishing Guard Backend',
        'version': '1.0.0',
        'cors_enabled': True,
        'api_endpoints': {
            'scan': '/api/scan/',
            'logs': '/api/logs/',
            'scan_logs': '/api/scan-logs/',
            'models_status': '/api/models/status/',
            'health': '/api/health/'
        }
    }, status=status.HTTP_200_OK)


@csrf_exempt
@api_view(['GET', 'POST', 'OPTIONS'])
def connection_test_view(request):
    """
    API endpoint for testing connection from the frontend.
    
    This endpoint helps verify that the backend is accessible and
    CORS is properly configured for frontend-backend communication.
    
    Args:
        request: HTTP request object
        
    Returns:
        Response: JSON response with connection status
    """
    if request.method == 'OPTIONS':
        return Response({'status': 'ok'}, status=status.HTTP_200_OK)
    
    return Response({
        'status': 'connected',
        'message': 'Backend connection successful',
        'timestamp': time.time(),
        'method': request.method,
        'headers': dict(request.headers),
        'cors_working': True
    }, status=status.HTTP_200_OK)


# --- Pagination Class ---
class ScanResultPagination(PageNumberPagination):
    """
    Custom pagination class for controlling result pagination.
    
    This class defines how scan results are divided into pages,
    allowing for efficient handling of large datasets.
    """
    page_size = 20  # Number of results per page
    page_size_query_param = 'page_size'  # Allow changing page size via URL parameter
    max_page_size = 100  # Maximum number of results per page


# --- ScanLogView Class ---
class ScanLogView(generics.ListAPIView):
    """
    View for reading all scan records from the database and returning them.
    
    This view uses Django REST Framework's ListAPIView which handles
    most of the heavy lifting for us, including serialization, pagination,
    filtering, and ordering.
    """
    queryset = ScanResult.objects.all().order_by('-timestamp')  # Get all records, ordered from newest to oldest
    serializer_class = ScanResultSerializer  # Use this serializer to convert to JSON
    pagination_class = ScanResultPagination  # Use custom pagination
    
    # Add search and ordering filters (with django_filters availability check)
    filter_backends = [SearchFilter, OrderingFilter]
    if DJANGO_FILTERS_AVAILABLE:
        filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    
    # Define fields that can be searched
    search_fields = ['url', 'result']
    
    # Define fields that results can be ordered by
    ordering_fields = ['timestamp', 'result', 'url']
    ordering = ['-timestamp']  # Default ordering
    
    # Define fields that can be filtered (only if django_filters is available)
    if DJANGO_FILTERS_AVAILABLE:
        filterset_fields = ['result']
    
    def get_queryset(self):
        """
        Optimize the query for better performance.
        
        This method allows for additional filtering based on query parameters,
        such as date ranges, to provide more targeted results.
        
        Returns:
            QuerySet: Filtered and optimized queryset
        """
        queryset = super().get_queryset()
        
        # Add optional date filtering
        date_from = self.request.query_params.get('date_from', None)
        date_to = self.request.query_params.get('date_to', None)
        
        if date_from:
            queryset = queryset.filter(timestamp__date__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__date__lte=date_to)
            
        return queryset