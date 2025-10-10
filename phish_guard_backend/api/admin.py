# api/admin.py

from django.contrib import admin
from .models import ScanResult # الخطوة الأولى: استيراد الموديل بتاعنا من ملف models.py

# Register your models here.

# الخطوة الثانية: تسجيل الموديل في موقع الأدمن
# السطر ده معناه: "يا لوحة التحكم، من فضلك اعرضي جدول ScanResult عندي"
admin.site.register(ScanResult)
