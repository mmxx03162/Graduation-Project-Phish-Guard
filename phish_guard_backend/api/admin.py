# api/admin.py

from django.contrib import admin
from .models import ScanResult, BlacklistedURL  # استيراد الموديلات من models.py

# Register your models here.

# تسجيل الموديلات في لوحة الـ Admin لمتابعة نتائج الـ scans والبلاك ليست.
admin.site.register(ScanResult)
admin.site.register(BlacklistedURL)
