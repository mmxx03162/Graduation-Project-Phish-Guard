import os
import sys
from pathlib import Path
import django

# 1. تعريف بيئة ديجانجو عشان الفايل المستقل ده يقدر يكلم الداتا بيز
# لما نشغل الملف مباشرةً (`python api/update_feeds.py`) لازم نضيف جذر مشروع Django للـ PYTHONPATH
BASE_DIR = Path(__file__).resolve().parents[1]  # .../phish_guard_backend
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phish_guard_backend.settings")
django.setup()

# 2. استدعاء الجدول اللي لسه عاملينه
from api.models import BlacklistedURL

def fetch_openphish_data():
    try:
        # ملاحظة: التحديث اليومي للبلاك ليست يتم عبر Django management command:
        #   python manage.py update_openphish_blacklist --limit 300
        # والملف ده مجرد wrapper للتشغيل اليدوي/التجربة.
        from django.core.management import call_command

        before = BlacklistedURL.objects.count()
        call_command("update_openphish_blacklist", limit=300)
        after = BlacklistedURL.objects.count()

        print(f"Blacklist updated. Inserted approx: {max(0, after - before)} URL(s).")
    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    fetch_openphish_data()