# api/views.py
# API Views for Phish-Guard Phishing Detection System
# Handles HTTP requests and responses for URL scanning

"""
═══════════════════════════════════════════════════════════════════════════════
API ENDPOINTS OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

POST /api/scan/
    - Main endpoint for URL scanning
    - Returns detailed analysis with verdict, reason, model votes, HTML analysis
    
GET /api/scan-logs/
    - Retrieve scan history with pagination, filtering, and search
    
GET /api/models/status/
    - Check status of loaded ML models
    
GET /api/health/
    - System health check
    
GET/POST /api/test-connection/
    - Test frontend-backend connectivity and CORS

═══════════════════════════════════════════════════════════════════════════════
"""

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import SearchFilter, OrderingFilter
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import ScanResult
from .serializers import ScanResultSerializer
from .predictor import make_final_prediction, get_models_status
import logging
import time

# Optional django_filters import
try:
    from django_filters.rest_framework import DjangoFilterBackend
    DJANGO_FILTERS_AVAILABLE = True
except ImportError:
    DJANGO_FILTERS_AVAILABLE = False
    DjangoFilterBackend = None

# Configure logging
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# CORS HELPER
# ═══════════════════════════════════════════════════════════════════════════

def add_cors_headers(response):
    """
    Add Cross-Origin Resource Sharing (CORS) headers to responses.
    Allows frontend applications to communicate with the backend API.
    
    Args:
        response: HTTP response object
        
    Returns:
        Response: Modified response with CORS headers
    """
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response['Access-Control-Allow-Credentials'] = 'true'
    return response

# ═══════════════════════════════════════════════════════════════════════════
# MAIN SCANNING ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════

@csrf_exempt
@api_view(['POST'])
def scan_url_view(request):
    """
    Main URL scanning endpoint.
    
    Performs 3-level analysis:
    1. Whitelist check
    2. AI model predictions (6 models)
    3. HTML content analysis (only if models flag as phishing)
    
    Request Body:
        {
            "url": "https://example.com"
        }
    
    Response:
        {
            "id": 123,
            "url": "https://example.com",
            "result": "Phishing" or "Legitimate",
            "reason": "Detailed explanation",
            "model_votes": {
                "total_votes": 6,
                "phishing_votes": 4,
                "legitimate_votes": 2,
                "models_verdict": "Phishing",
                "detailed_votes": [...]
            },
            "html_analysis": {
                "suspicious": true,
                "evidence": [...],
                "score": 80
            },
            "timestamp": "2024-01-01T12:00:00Z",
            "processing_time": 1.234,
            "status": "success"
        }
    
    Args:
        request: HTTP request with URL in body
        
    Returns:
        Response: JSON response with analysis results
    """
    start_time = time.time()
    
    try:
        # ───────────────────────────────────────────────────────────────────
        # Validate Request Data
        # ───────────────────────────────────────────────────────────────────
        serializer = ScanResultSerializer(data=request.data)
        
        if not serializer.is_valid():
            logger.warning(f"Invalid request data: {serializer.errors}")
            return Response({
                'status': 'error',
                'message': 'Invalid request data',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # ───────────────────────────────────────────────────────────────────
        # Extract URL and Perform Analysis
        # ───────────────────────────────────────────────────────────────────
        url_to_check = serializer.validated_data['url']
        logger.info(f"Starting analysis for URL: {url_to_check}")
        
        # Perform 3-level prediction
        prediction_data = make_final_prediction(url_to_check)
        
        # Extract results
        final_verdict = prediction_data.get("verdict", "Legitimate")
        prediction_reason = prediction_data.get("reason", "Analysis completed")
        model_votes = prediction_data.get("model_votes")
        html_analysis = prediction_data.get("html_analysis")
        
        # ───────────────────────────────────────────────────────────────────
        # Save to Database
        # ───────────────────────────────────────────────────────────────────
        scan_result = serializer.save(result=final_verdict)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # ───────────────────────────────────────────────────────────────────
        # Prepare Response
        # ───────────────────────────────────────────────────────────────────
        response_data = {
            'id': scan_result.id,
            'url': scan_result.url,
            'result': scan_result.result,
            'reason': prediction_reason,
            'model_votes': model_votes,
            'html_analysis': html_analysis,
            'timestamp': scan_result.timestamp,
            'processing_time': round(processing_time, 3),
            'status': 'success'
        }
        
        logger.info(
            f"Analysis completed: {final_verdict} "
            f"(Reason: {prediction_reason}, Time: {processing_time:.3f}s)"
        )
        
        return Response(response_data, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        logger.error(f"Error processing scan request: {str(e)}", exc_info=True)
        return Response({
            'status': 'error',
            'message': 'Internal server error during URL analysis',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ═══════════════════════════════════════════════════════════════════════════
# MODELS STATUS ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════

@csrf_exempt
@api_view(['GET'])
def models_status_view(request):
    """
    Check the loading status of all ML models.
    
    Returns information about which models are loaded and ready.
    Useful for system monitoring and debugging.
    
    Response:
        {
            "status": "success",
            "models_loaded": "6/7",
            "models_status": {
                "Random Forest": true,
                "LightGBM": true,
                ...
            },
            "all_models_ready": true
        }
    
    Args:
        request: HTTP request
        
    Returns:
        Response: JSON with model status information
    """
    try:
        models_status = get_models_status()
        loaded_count = sum(models_status.values())
        total_count = len(models_status)
        
        return Response({
            'status': 'success',
            'models_loaded': f"{loaded_count}/{total_count}",
            'models_status': models_status,
            'all_models_ready': loaded_count == total_count,
            'message': (
                'All models operational' if loaded_count == total_count
                else f'Warning: Only {loaded_count}/{total_count} models loaded'
            )
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error getting models status: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Unable to retrieve model status',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ═══════════════════════════════════════════════════════════════════════════
# HEALTH CHECK ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════

@csrf_exempt
@api_view(['GET'])
def health_check_view(request):
    """
    System health verification endpoint.
    
    Provides information about service status and available endpoints.
    
    Response:
        {
            "status": "healthy",
            "service": "Phishing Guard Backend",
            "version": "2.0.0",
            "api_endpoints": {...}
        }
    
    Args:
        request: HTTP request
        
    Returns:
        Response: JSON with system health information
    """
    return Response({
        'status': 'healthy',
        'service': 'Phishing Guard Backend',
        'version': '2.0.0',
        'cors_enabled': True,
        'features': [
            'Multi-level URL analysis',
            'AI model ensemble (6 models)',
            'HTML content inspection',
            'Whitelist protection'
        ],
        'api_endpoints': {
            'scan': '/api/scan/',
            'scan_logs': '/api/scan-logs/',
            'models_status': '/api/models/status/',
            'health': '/api/health/',
            'test_connection': '/api/test-connection/'
        }
    }, status=status.HTTP_200_OK)

# ═══════════════════════════════════════════════════════════════════════════
# CONNECTION TEST ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════

@csrf_exempt
@api_view(['GET', 'POST', 'OPTIONS'])
def connection_test_view(request):
    """
    Test frontend-backend connectivity and CORS configuration.
    
    Useful for debugging connection issues between frontend and backend.
    
    Args:
        request: HTTP request
        
    Returns:
        Response: JSON with connection details
    """
    if request.method == 'OPTIONS':
        return Response({'status': 'ok'}, status=status.HTTP_200_OK)
    
    return Response({
        'status': 'connected',
        'message': 'Backend connection successful',
        'timestamp': time.time(),
        'method': request.method,
        'cors_working': True,
        'server_info': {
            'service': 'Phishing Guard',
            'version': '2.0.0'
        }
    }, status=status.HTTP_200_OK)

# ═══════════════════════════════════════════════════════════════════════════
# PAGINATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

class ScanResultPagination(PageNumberPagination):
    """
    Custom pagination for scan results.
    
    Divides results into pages for efficient data retrieval.
    """
    page_size = 20  # Default items per page
    page_size_query_param = 'page_size'  # Allow custom page size via URL
    max_page_size = 100  # Maximum allowed page size

# ═══════════════════════════════════════════════════════════════════════════
# SCAN LOGS ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════

class ScanLogView(generics.ListAPIView):
    """
    Retrieve scan history with advanced filtering.
    
    Features:
    - Pagination (20 items per page)
    - Search by URL or result
    - Filter by result type (Phishing/Legitimate)
    - Order by timestamp, result, or URL
    - Date range filtering
    
    Query Parameters:
        - page: Page number (default: 1)
        - page_size: Items per page (default: 20, max: 100)
        - search: Search in URL and result fields
        - ordering: Sort by field (e.g., -timestamp, url)
        - result: Filter by result (Phishing or Legitimate)
        - date_from: Filter scans from this date
        - date_to: Filter scans until this date
    
    Example Requests:
        GET /api/scan-logs/
        GET /api/scan-logs/?page=2&page_size=50
        GET /api/scan-logs/?search=google
        GET /api/scan-logs/?result=Phishing
        GET /api/scan-logs/?ordering=-timestamp
        GET /api/scan-logs/?date_from=2024-01-01&date_to=2024-01-31
    """
    queryset = ScanResult.objects.all().order_by('-timestamp')
    serializer_class = ScanResultSerializer
    pagination_class = ScanResultPagination
    
    # Configure filters
    filter_backends = [SearchFilter, OrderingFilter]
    if DJANGO_FILTERS_AVAILABLE:
        filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    
    # Searchable fields
    search_fields = ['url', 'result']
    
    # Orderable fields
    ordering_fields = ['timestamp', 'result', 'url']
    ordering = ['-timestamp']  # Default: newest first
    
    # Filterable fields (if django_filters available)
    if DJANGO_FILTERS_AVAILABLE:
        filterset_fields = ['result']
    
    def get_queryset(self):
        """
        Get queryset with optional date filtering.
        
        Returns:
            QuerySet: Filtered scan results
        """
        queryset = super().get_queryset()
        
        # Date range filtering
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        
        if date_from:
            try:
                queryset = queryset.filter(timestamp__date__gte=date_from)
            except Exception as e:
                logger.warning(f"Invalid date_from parameter: {e}")
        
        if date_to:
            try:
                queryset = queryset.filter(timestamp__date__lte=date_to)
            except Exception as e:
                logger.warning(f"Invalid date_to parameter: {e}")
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        """
        Override list method to add metadata to response.
        
        Returns:
            Response: Paginated results with metadata
        """
        response = super().list(request, *args, **kwargs)
        
        # Add metadata
        response.data['metadata'] = {
            'total_scans': self.get_queryset().count(),
            'phishing_count': self.get_queryset().filter(result='Phishing').count(),
            'legitimate_count': self.get_queryset().filter(result='Legitimate').count(),
        }
        
        return response

# ═══════════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY
# ═══════════════════════════════════════════════════════════════════════════

# Keep old endpoint names for backward compatibility
logs_view = ScanLogView.as_view()  # For /api/logs/ endpoint