from django.urls import path
from . import views

urlpatterns = [
    # الـ endpoint الأساسي لفحص الـ URLs
    path('scan/', views.scan_url_view, name='scan_url'),
    
    # endpoint لعرض سجلات الفحص
    path('scan-logs/', views.ScanLogView.as_view(), name='scan_logs'),
    path('logs/', views.ScanLogView.as_view(), name='logs'),  # للتوافق مع الواجهة الأمامية
    
    # endpoints إضافية للمراقبة والتشخيص
    path('models/status/', views.models_status_view, name='models_status'),
    path('health/', views.health_check_view, name='health_check'),
    path('test/', views.connection_test_view, name='connection_test'),  # اختبار الاتصال
]