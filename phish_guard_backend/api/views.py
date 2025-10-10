# api/views.py - نسخة محسنة

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

# استيراد اختياري لـ django_filters
try:
    from django_filters.rest_framework import DjangoFilterBackend
    DJANGO_FILTERS_AVAILABLE = True
except ImportError:
    DJANGO_FILTERS_AVAILABLE = False
    DjangoFilterBackend = None

# إعداد الـ logging
logger = logging.getLogger(__name__)

def add_cors_headers(response):
    """
    إضافة CORS headers للاستجابة
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
    API endpoint لفحص الـ URLs وتحديد ما إذا كانت phishing أم لا
    """
    start_time = time.time()
    
    try:
        # التحقق من البيانات المرسلة
        serializer = ScanResultSerializer(data=request.data)
        
        if serializer.is_valid():
            # استخراج الـ URL
            url_to_check = serializer.validated_data['url']
            logger.info(f"Analyzing URL: {url_to_check}")
            
            # التنبؤ باستخدام الموديلات
            prediction_result = make_prediction(url_to_check)
            
            # حساب وقت المعالجة
            processing_time = time.time() - start_time
            
            # حفظ النتيجة في قاعدة البيانات
            scan_result = serializer.save(result=prediction_result)
            
            # إعداد الاستجابة
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
    API endpoint لعرض حالة الموديلات
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
    API endpoint للتحقق من صحة النظام
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
    API endpoint لاختبار الاتصال من الواجهة الأمامية
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
    كلاس للتحكم في التقسيم (Pagination) للنتائج
    """
    page_size = 20  # عدد النتائج في كل صفحة
    page_size_query_param = 'page_size'  # إمكانية تغيير حجم الصفحة من الـ URL
    max_page_size = 100  # الحد الأقصى للنتائج في الصفحة الواحدة


# --- ScanLogView Class ---
class ScanLogView(generics.ListAPIView):
    """
    هذا الـ View يقرأ كل سجلات الفحص من قاعدة البيانات ويرجعها.
    ListAPIView يقوم بكل العمل الشاق بالنيابة عنا.
    """
    queryset = ScanResult.objects.all().order_by('-timestamp')  # 1. احصل على كل السجلات، ورتبها من الأحدث للأقدم
    serializer_class = ScanResultSerializer  # 2. استخدم هذا الـ Serializer لتحويلها إلى JSON
    pagination_class = ScanResultPagination  # 3. استخدم التقسيم المخصص
    
    # 4. إضافة فلاتر البحث والترتيب (مع التحقق من توفر django_filters)
    filter_backends = [SearchFilter, OrderingFilter]
    if DJANGO_FILTERS_AVAILABLE:
        filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    
    # 5. تحديد الحقول التي يمكن البحث فيها
    search_fields = ['url', 'result']
    
    # 6. تحديد الحقول التي يمكن ترتيب النتائج حسبها
    ordering_fields = ['timestamp', 'result', 'url']
    ordering = ['-timestamp']  # الترتيب الافتراضي
    
    # 7. تحديد الحقول التي يمكن فلترتها (فقط إذا كان django_filters متوفر)
    if DJANGO_FILTERS_AVAILABLE:
        filterset_fields = ['result']
    
    def get_queryset(self):
        """
        تحسين الاستعلام لتحسين الأداء
        """
        queryset = super().get_queryset()
        
        # إضافة فلتر حسب التاريخ (اختياري)
        date_from = self.request.query_params.get('date_from', None)
        date_to = self.request.query_params.get('date_to', None)
        
        if date_from:
            queryset = queryset.filter(timestamp__date__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__date__lte=date_to)
            
        return queryset