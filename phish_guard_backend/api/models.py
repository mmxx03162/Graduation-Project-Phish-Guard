# api/models.py

from django.db import models

# Create your models here.
class ScanResult(models.Model):
    # الحقل اللي هنخزن فيه اللينك اللي تم إرساله
    # URLField هو نوع مخصص للينكات، max_length ضروري لأي حقل نصي
    url = models.URLField(max_length=2000 )

    # الحقل اللي هنخزن فيه النتيجة (مثلاً: "Phishing" أو "Legitimate")
    # CharField هو حقل نصي قصير
    result = models.CharField(max_length=20 , default="Phishing")

    # الحقل اللي هيسجل تاريخ ووقت إنشاء الصف ده في الجدول
    # auto_now_add=True معناها إن ديجانجو هيحط الوقت الحالي تلقائيًا أول ما الصف يتสร้าง بس
    # ومش هيتغير بعد كده
    reason = models.TextField(null=True, blank=True) 
    timestamp = models.DateTimeField(auto_now_add=True)

    # دي دالة خاصة في بايثون عشان تحدد شكل الـ object ده لما نيجي نطبعه
    # هتفيدنا جدًا في لوحة التحكم بعدين عشان نشوف اللينك بدل ما نشوف "(Object (1"
    def __str__(self):
        return self.url
    
    
    
    
    
    
    
    