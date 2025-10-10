
# # test_models.py - ملف لاختبار الموديلات قبل استخدامها في الـ API

# import sys
# import os

# # إضافة مسار الـ project للـ Python path
# project_root = os.path.dirname(os.path.abspath(__file__))
# sys.path.insert(0, project_root)

# from api.predictor import make_prediction, get_models_status

# def test_models():
#     """اختبار شامل للموديلات مع URLs مختلفة"""
    
#     print("="*80)
#     print("TESTING PHISHING DETECTION MODELS")
#     print("="*80)
    
#     # عرض حالة الموديلات
#     get_models_status()
    
#     # URLs للاختبار
#     test_urls = [
#         # URLs شرعية
#         ("https://www.google.com", "Legitimate"),
#         ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "Legitimate"),
#         ("https://stackoverflow.com/questions/tagged/python", "Legitimate"),
#         ("https://github.com/microsoft/vscode", "Legitimate"),
#         ("https://developer.mozilla.org/en-US/docs/Web/JavaScript", "Legitimate"),
        
#         # URLs مشبوهة
#         ("http://paypal-security-update.suspicious-domain.tk/login", "Phishing"),
#         ("https://www.goog1e.com/accounts/signin", "Phishing"),
#         ("http://192.168.1.100/paypal/update.html", "Phishing"),
#         ("https://amazon-account-verification.web.app/confirm", "Phishing"),
#         ("http://secure-banking-login.ml/verify", "Phishing"),
#     ]
    
#     print(f"\nTesting {len(test_urls)} URLs...")
    
#     results = []
#     correct_predictions = 0
    
#     for i, (url, expected) in enumerate(test_urls, 1):
#         print(f"\n{'-'*60}")
#         print(f"Test {i}: {url}")
#         print(f"Expected: {expected}")
        
#         try:
#             prediction = make_prediction(url)
            
#             # تحديد النتيجة
#             is_correct = prediction == expected
#             if is_correct:
#                 correct_predictions += 1
#                 result_icon = "✅"
#             else:
#                 result_icon = "❌"
            
#             print(f"Result: {result_icon} {prediction}")
            
#             results.append({
#                 'url': url,
#                 'expected': expected,
#                 'predicted': prediction,
#                 'correct': is_correct
#             })
            
#         except Exception as e:
#             print(f"❌ Error: {e}")
#             results.append({
#                 'url': url,
#                 'expected': expected,
#                 'predicted': 'Error',
#                 'correct': False
#             })
    
#     # ملخص النتائج
#     print("\n" + "="*80)
#     print("SUMMARY")
#     print("="*80)
    
#     accuracy = (correct_predictions / len(test_urls)) * 100
#     print(f"Overall Accuracy: {correct_predictions}/{len(test_urls)} ({accuracy:.1f}%)")
    
#     # تفصيل النتائج الخاطئة
#     incorrect_results = [r for r in results if not r['correct']]
#     if incorrect_results:
#         print(f"\nIncorrect Predictions ({len(incorrect_results)}):")
#         for result in incorrect_results:
#             print(f"  - {result['url']}")
#             print(f"    Expected: {result['expected']}, Got: {result['predicted']}")
#     else:
#         print("\n🎉 All predictions were correct!")
    
#     return results

# def test_specific_url():
#     """اختبار URL محدد"""
#     while True:
#         url = input("\nEnter URL to test (or 'quit' to exit): ").strip()
#         if url.lower() in ['quit', 'exit', 'q']:
#             break
        
#         if url:
#             try:
#                 result = make_prediction(url)
#                 print(f"\nResult for '{url}': {result}")
#             except Exception as e:
#                 print(f"Error: {e}")
#         else:
#             print("Please enter a valid URL")

# def main():
#     """الدالة الرئيسية"""
#     print("Phishing Detection Models Test Suite")
#     print("1. Run comprehensive test")
#     print("2. Test specific URL")
#     print("3. Show models status only")
    
#     choice = input("\nEnter your choice (1-3): ").strip()
    
#     if choice == "1":
#         test_models()
#     elif choice == "2":
#         test_specific_url()
#     elif choice == "3":
#         get_models_status()
#     else:
#         print("Invalid choice")

# if __name__ == "__main__":
#     main()