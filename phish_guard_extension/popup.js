// هذا السطر يضمن أن الكود الخاص بنا لن يعمل إلا بعد تحميل صفحة الـ HTML بالكامل
document.addEventListener('DOMContentLoaded', function() {

    // 1. العثور على العناصر التي سنتعامل معها في ملف الـ HTML
    const checkButton = document.getElementById('checkButton');
    const resultDiv = document.getElementById('result');

    // 2. إضافة "مستمع" لحدث النقر على الزر
    // هذا يعني: "عندما يتم النقر على الزر، قم بتنفيذ هذه الدالة"
    checkButton.addEventListener('click', function() {
        
        // عرض رسالة "جاري الفحص..." فورًا لإعلام المستخدم
        resultDiv.textContent = 'Checking...';
        resultDiv.style.color = 'orange';

        // 3. طلب رابط الصفحة الحالية من كروم
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const currentUrl = tabs[0].url;

            // 4. إرسال الرابط إلى الـ API الخاص بنا في Django
            fetch('http://127.0.0.1:8000/api/scan/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                // نقوم بتحويل بياناتنا إلى صيغة JSON
                body: JSON.stringify({ url: currentUrl }),
            })
            .then(response => {
                // التأكد من أن الرد من السيرفر سليم
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json(); // تحويل الرد إلى JSON
            })
            .then(data => {
                // 5. عرض النتيجة النهائية التي عادت من Django
                displayResult(data.result);
            })
            .catch(error => {
                // 6. في حالة حدوث أي خطأ (مثل أن سيرفر Django لا يعمل)
                console.error('Error:', error);
                displayResult('Error: Could not connect to server.');
            });
        });
    });

    // دالة مساعدة لتغيير لون وشكل النتيجة
    function displayResult(resultText) {
        resultDiv.textContent = resultText;
        if (resultText.toLowerCase() === 'phishing') {
            resultDiv.style.color = 'red';
        } else if (resultText.toLowerCase() === 'legitimate') {
            resultDiv.style.color = 'green';
        } else {
            resultDiv.style.color = 'black'; // للرسائل الأخرى مثل الأخطاء
        }
    }
});