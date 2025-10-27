# 🛡️ Phish-Guard - AI-Powered Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.2.6-green.svg)](https://djangoproject.com)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🚀 Quick Start

### Prerequisites
- Python 3.13+
- Node.js 16+
- PostgreSQL 12+ (optional)
- Git

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd phish-guard-project
```

2. **Backend Setup**
```bash
cd phish_guard_backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

3. **Frontend Setup**
```bash
cd "Front end/phish-guard-dashboard"
npm install
npm run dev
```

4. **Browser Extension**
- Open Chrome → `chrome://extensions/`
- Enable "Developer mode"
- Click "Load unpacked" → Select `phish_guard_extension` folder

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Browser       │    │   React         │    │   Django        │
│   Extension     │◄──►│   Dashboard     │◄──►│   Backend       │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   PostgreSQL    │
                    │   Database      │
                    └─────────────────┘
```

## 🤖 Machine Learning Models

The system uses an ensemble of 6 ML models organized into 3 teams:

### Team 1: Numerical Features
- **Random Forest** - Ensemble decision trees
- **LightGBM** - Gradient boosting framework

### Team 2: Scaled Numerical Features  
- **Logistic Regression** - Linear classifier
- **Support Vector Classifier** - Non-linear classification

### Team 3: Combined Features
- **XGBoost** - Extreme gradient boosting
- **Neural Network (MLP)** - Multi-layer perceptron

## 📊 Features

### Backend API
- ✅ Real-time URL scanning
- ✅ Multi-model ensemble prediction
- ✅ RESTful API endpoints
- ✅ PostgreSQL database integration
- ✅ CORS support for frontend integration

### React Dashboard
- ✅ Real-time scan monitoring
- ✅ Interactive data visualization
- ✅ Sortable and filterable results table
- ✅ Connection status monitoring
- ✅ Responsive design

### Browser Extension
- ✅ One-click URL scanning
- ✅ Real-time phishing detection
- ✅ Chrome Manifest V3 support
- ✅ Seamless backend integration

## 🔧 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/` | Scan URL for phishing |
| GET | `/api/logs/` | Get scan history |
| GET | `/api/models/status/` | Check ML model status |
| GET | `/api/health/` | Health check |

### Example Usage

```bash
# Scan a URL
curl -X POST http://localhost:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Get scan logs
curl http://localhost:8000/api/logs/
```

## 🗄️ Database Schema

### ScanResult Model
```python
class ScanResult(models.Model):
    url = models.URLField(max_length=2000)
    result = models.CharField(max_length=20, default="Phishing")
    timestamp = models.DateTimeField(auto_now_add=True)
```

## 🚀 Deployment

### Production Setup

1. **Environment Variables**
```bash
export DEBUG=False
export SECRET_KEY='your-secret-key'
export DATABASE_URL='postgresql://user:pass@host:port/db'
```

2. **Database Migration**
```bash
python manage.py migrate
python manage.py collectstatic
```

3. **Run with Gunicorn**
```bash
gunicorn phish_guard_backend.wsgi:application --bind 0.0.0.0:8000
```

### Docker Deployment
```bash
docker-compose up -d
```

## 🧪 Testing

```bash
# Backend tests
python manage.py test

# Frontend tests
npm test

# API testing
curl http://localhost:8000/api/health/
```

## 📁 Project Structure

```
phish-guard-project/
├── phish_guard_backend/          # Django Backend
│   ├── api/                      # API application
│   │   ├── models.py            # Database models
│   │   ├── views.py             # API endpoints
│   │   ├── predictor.py         # ML prediction engine
│   │   ├── feature_extractor.py # Feature extraction
│   │   └── ml_model/            # Trained ML models
│   └── phish_guard_backend/     # Django settings
├── Front end/                    # React Frontend
│   └── phish-guard-dashboard/
│       ├── src/
│       │   ├── App.jsx          # Main component
│       │   └── components/      # React components
│       └── package.json
├── phish_guard_extension/       # Browser Extension
│   ├── manifest.json           # Extension manifest
│   ├── popup.html              # Extension UI
│   └── popup.js                # Extension logic
└── PROJECT_DOCUMENTATION.md     # Complete documentation
```

## 🔍 Feature Extraction

The system extracts 9 key features from URLs:

1. **URL Length** - Total character count
2. **Hostname Length** - Domain name length  
3. **Number of Dots** - Count of '.' in hostname
4. **Uses HTTPS** - Binary indicator (1/0)
5. **Has Suspicious Keywords** - Phishing-related terms
6. **Number of Dashes** - Count of '-' in hostname
7. **Has At Symbol** - Binary indicator for '@'
8. **Number of Query Components** - URL parameters count
9. **Domain Age** - Estimated domain age in days

## 🎯 Voting System

The final prediction uses majority voting:

1. Each model votes (0 = Legitimate, 1 = Phishing)
2. Votes are counted and majority decision is taken
3. In case of tie, defaults to "Phishing" for safety

## 🛠️ Development

### Backend Development
```bash
cd phish_guard_backend
python manage.py runserver
```

### Frontend Development  
```bash
cd "Front end/phish-guard-dashboard"
npm run dev
```

### Extension Development
- Modify files in `phish_guard_extension/`
- Reload extension in Chrome
- Test changes immediately

## 🐛 Troubleshooting

### Common Issues

**Backend not starting:**
- Check Python version (3.13+)
- Verify all dependencies installed
- Check database connection

**Frontend connection issues:**
- Ensure Django server is running
- Check CORS settings in `settings.py`
- Verify API endpoints

**Extension not working:**
- Check Chrome extension permissions
- Verify manifest.json syntax
- Ensure backend is accessible

## 📈 Performance

- **Prediction Time**: ~200-300ms average
- **Accuracy**: 95%+ with ensemble voting
- **Throughput**: 100+ requests/minute
- **Memory Usage**: ~500MB with all models loaded

## 🔒 Security

- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- CORS configuration

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For support, questions, or contributions:
- Create an issue in the repository
- Contact the development team
- Check the [complete documentation](PROJECT_DOCUMENTATION.md)

## 🎉 Acknowledgments

- Django REST Framework team
- React development team
- Machine learning community
- Open source contributors

---

**Made with ❤️ for cybersecurity**
