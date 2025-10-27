# Phish-Guard Project Documentation
## Complete Project Documentation from Start to End

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Technology Stack](#technology-stack)
4. [Project Structure](#project-structure)
5. [Installation & Setup](#installation--setup)
6. [Backend Documentation](#backend-documentation)
7. [Frontend Documentation](#frontend-documentation)
8. [Browser Extension Documentation](#browser-extension-documentation)
9. [Machine Learning Models](#machine-learning-models)
10. [API Documentation](#api-documentation)
11. [Database Schema](#database-schema)
12. [Deployment Guide](#deployment-guide)
13. [Testing](#testing)
14. [Troubleshooting](#troubleshooting)
15. [Future Enhancements](#future-enhancements)

---

## Project Overview

### What is Phish-Guard?
Phish-Guard is an AI-powered phishing detection system that combines multiple machine learning models to identify malicious websites in real-time. The system consists of three main components:

1. **Django Backend API** - Handles URL analysis and machine learning predictions
2. **React Dashboard** - Provides a web interface for monitoring scan results
3. **Browser Extension** - Allows users to scan websites directly from their browser

### Key Features
- **Multi-Model AI Detection**: Uses 6 different machine learning models for accurate phishing detection
- **Real-time Analysis**: Instant URL scanning and classification
- **Web Dashboard**: Comprehensive monitoring and statistics
- **Browser Integration**: Seamless browser extension for immediate protection
- **RESTful API**: Easy integration with other applications
- **Cross-Platform**: Works on Windows, macOS, and Linux

### Target Users
- **Individual Users**: Personal protection against phishing attacks
- **Organizations**: Enterprise-level phishing protection
- **Developers**: API integration for custom applications
- **Security Researchers**: Analysis and research tools

---

## System Architecture

### High-Level Architecture
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

### Component Interaction Flow
1. **User Action**: User clicks "Check Current Site" in browser extension or submits URL via dashboard
2. **API Request**: Frontend sends HTTP request to Django backend
3. **Feature Extraction**: Backend extracts features from the URL
4. **ML Prediction**: Multiple machine learning models analyze the features
5. **Voting System**: Models vote on the classification result
6. **Database Storage**: Result is stored in PostgreSQL database
7. **Response**: Classification result is returned to the frontend
8. **UI Update**: Frontend displays the result to the user

---

## Technology Stack

### Backend Technologies
- **Framework**: Django 5.2.6
- **Database**: PostgreSQL (with SQLite fallback)
- **API**: Django REST Framework
- **Machine Learning**: 
  - scikit-learn
  - XGBoost
  - LightGBM
  - Neural Networks (MLP)
- **CORS**: django-cors-headers
- **Python Version**: 3.13+

### Frontend Technologies
- **Framework**: React 18+
- **Build Tool**: Vite
- **Styling**: CSS3 with modern features
- **HTTP Client**: Fetch API
- **State Management**: React Hooks (useState, useEffect)

### Browser Extension
- **Manifest**: Version 3
- **JavaScript**: Vanilla ES6+
- **Chrome APIs**: tabs, activeTab
- **Communication**: Fetch API to backend

### Development Tools
- **Version Control**: Git
- **Package Management**: npm (frontend), pip (backend)
- **Virtual Environment**: Python venv
- **Code Editor**: VS Code (recommended)

---

## Project Structure

```
phish-guard-project/
├── phish_guard_backend/           # Django Backend
│   ├── api/                       # Main API application
│   │   ├── models.py             # Database models
│   │   ├── views.py              # API endpoints
│   │   ├── serializers.py        # Data serialization
│   │   ├── predictor.py          # ML prediction engine
│   │   ├── feature_extractor.py  # Feature extraction
│   │   ├── urls.py              # URL routing
│   │   └── ml_model/            # Trained ML models
│   │       ├── new_model_1_1_rf.joblib
│   │       ├── new_model_1_2_lgbm.joblib
│   │       ├── new_model_2_1_lr.joblib
│   │       ├── new_model_2_2_svc.joblib
│   │       ├── new_model_3_1_xgb.joblib
│   │       ├── new_model_3_2_mlp.joblib
│   │       ├── new_scaler_team2.joblib
│   │       ├── new_scaler_team3.joblib
│   │       └── new_tfidf_vectorizer_team3.joblib
│   ├── phish_guard_backend/     # Django project settings
│   │   ├── settings.py          # Project configuration
│   │   ├── urls.py              # Main URL routing
│   │   ├── wsgi.py              # WSGI configuration
│   │   └── asgi.py              # ASGI configuration
│   ├── manage.py                # Django management script
│   └── requirements.txt         # Python dependencies
├── Front end/                    # React Frontend
│   └── phish-guard-dashboard/
│       ├── src/
│       │   ├── App.jsx          # Main React component
│       │   ├── components/
│       │   │   ├── ScanLogTable.jsx
│       │   │   └── ScanSummaryChart.jsx
│       │   ├── App.css          # Main styles
│       │   └── main.jsx        # React entry point
│       ├── package.json         # Node.js dependencies
│       └── vite.config.js      # Vite configuration
├── phish_guard_extension/       # Browser Extension
│   ├── manifest.json           # Extension manifest
│   ├── popup.html              # Extension popup UI
│   ├── popup.js                # Extension logic
│   └── icon.png                # Extension icon
└── README.md                   # Project documentation
```

---

## Installation & Setup

### Prerequisites
- Python 3.13+
- Node.js 16+
- PostgreSQL 12+ (optional, SQLite can be used)
- Git

### Backend Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd phish-guard-project
```

2. **Create virtual environment**
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

3. **Install dependencies**
```bash
cd phish_guard_backend
pip install -r requirements.txt
```

4. **Database setup**
```bash
# For PostgreSQL (recommended)
# Create database: phish_guard_backend
# Update settings.py with your database credentials

# For SQLite (development)
# Uncomment SQLite configuration in settings.py
```

5. **Run migrations**
```bash
python manage.py makemigrations
python manage.py migrate
```

6. **Create superuser (optional)**
```bash
python manage.py createsuperuser
```

7. **Start development server**
```bash
python manage.py runserver
```

### Frontend Setup

1. **Navigate to frontend directory**
```bash
cd "Front end/phish-guard-dashboard"
```

2. **Install dependencies**
```bash
npm install
```

3. **Start development server**
```bash
npm run dev
```

### Browser Extension Setup

1. **Load extension in Chrome**
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `phish_guard_extension` folder

2. **Test the extension**
   - Visit any website
   - Click the Phish-Guard extension icon
   - Click "Check Current Site"

---

## Backend Documentation

### Django Project Structure

The backend is built using Django 5.2.6 with the following key components:

#### Models (`api/models.py`)
```python
class ScanResult(models.Model):
    """
    Model representing a URL scan result in the database.
    """
    url = models.URLField(max_length=2000)
    result = models.CharField(max_length=20, default="Phishing")
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.url
```

#### Views (`api/views.py`)
The API provides several endpoints:

- **POST /api/scan/** - Scan a URL for phishing
- **GET /api/logs/** - Retrieve scan history
- **GET /api/models/status/** - Check ML model status
- **GET /api/health/** - Health check endpoint

#### Machine Learning Engine (`api/predictor.py`)

The prediction system uses a voting mechanism with 6 different models:

1. **Team 1 - Numerical Features**:
   - Random Forest
   - LightGBM

2. **Team 2 - Scaled Numerical Features**:
   - Logistic Regression
   - Support Vector Classifier

3. **Team 3 - Combined Features**:
   - XGBoost
   - Neural Network (MLP)

#### Feature Extraction (`api/feature_extractor.py`)

The system extracts 9 key features from URLs:

1. URL Length
2. Hostname Length
3. Number of Dots
4. Uses HTTPS
5. Has Suspicious Keywords
6. Number of Dashes
7. Has At Symbol
8. Number of Query Components
9. Domain Age (estimated)

### API Endpoints

#### Scan URL
```http
POST /api/scan/
Content-Type: application/json

{
    "url": "https://example.com"
}
```

**Response:**
```json
{
    "id": 1,
    "url": "https://example.com",
    "result": "Legitimate",
    "timestamp": "2024-01-15T10:30:00Z",
    "processing_time": 0.245,
    "status": "success"
}
```

#### Get Scan Logs
```http
GET /api/logs/
```

**Response:**
```json
{
    "count": 100,
    "next": "http://localhost:8000/api/logs/?page=2",
    "previous": null,
    "results": [
        {
            "id": 1,
            "url": "https://example.com",
            "result": "Legitimate",
            "timestamp": "2024-01-15T10:30:00Z"
        }
    ]
}
```

#### Models Status
```http
GET /api/models/status/
```

**Response:**
```json
{
    "status": "success",
    "models_loaded": "6/6",
    "models_status": {
        "Team 1": {
            "Random Forest": true,
            "LightGBM": true
        },
        "Team 2": {
            "Logistic Regression": true,
            "SVC": true,
            "StandardScaler": true
        },
        "Team 3": {
            "XGBoost": true,
            "Neural Network": true,
            "TF-IDF Vectorizer": true,
            "Scaler": true
        }
    },
    "all_models_ready": true
}
```

---

## Frontend Documentation

### React Application Structure

The frontend is built using React 18+ with modern hooks and functional components.

#### Main Component (`App.jsx`)

The main App component manages:
- Backend connection status
- Data fetching and state management
- Error handling
- Auto-refresh functionality

**Key Features:**
- Real-time connection monitoring
- Automatic data refresh every 30 seconds
- Comprehensive error handling
- Responsive design

#### Components

##### ScanLogTable (`components/ScanLogTable.jsx`)
- Displays scan results in a sortable table
- Provides filtering by result type
- Shows clickable URLs
- Responsive design

##### ScanSummaryChart (`components/ScanSummaryChart.jsx`)
- Visual pie chart representation
- Statistics cards
- Real-time updates
- Interactive legend

### State Management

The application uses React hooks for state management:

```javascript
const [scans, setScans] = useState([]);
const [loading, setLoading] = useState(true);
const [error, setError] = useState(null);
const [backendConnected, setBackendConnected] = useState(false);
```

### API Integration

The frontend communicates with the backend using the Fetch API:

```javascript
const response = await fetch('http://127.0.0.1:8000/api/logs/', {
    method: 'GET',
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    },
    mode: 'cors',
});
```

---

## Browser Extension Documentation

### Extension Structure

The browser extension is built using Chrome Extension Manifest V3.

#### Manifest (`manifest.json`)
```json
{
    "manifest_version": 3,
    "name": "Phish-Guard",
    "description": "An AI-powered extension to detect phishing websites in real-time.",
    "version": "1.0",
    "action": {
        "default_popup": "popup.html",
        "default_icon": "icon.png"
    },
    "permissions": [
        "activeTab",
        "tabs"
    ],
    "host_permissions": [
        "http://127.0.0.1:8000/*"
    ]
}
```

#### Popup Interface (`popup.html`)
- Simple, clean interface
- Single "Check Current Site" button
- Result display area
- Responsive design

#### Extension Logic (`popup.js`)
- Gets current tab URL using Chrome APIs
- Sends scan request to Django backend
- Displays results with appropriate styling
- Handles errors gracefully

### Extension Workflow

1. User clicks extension icon
2. Extension gets current tab URL
3. Sends POST request to `/api/scan/`
4. Displays result with color coding:
   - Red for phishing
   - Green for legitimate
   - Black for errors

---

## Machine Learning Models

### Model Architecture

The system uses an ensemble approach with 6 different machine learning models organized into 3 teams:

#### Team 1: Numerical Features
- **Random Forest**: Ensemble method using multiple decision trees
- **LightGBM**: Gradient boosting framework optimized for speed

#### Team 2: Scaled Numerical Features
- **Logistic Regression**: Linear classifier with scaled features
- **Support Vector Classifier**: Non-linear classification with RBF kernel

#### Team 3: Combined Features
- **XGBoost**: Extreme gradient boosting with combined text and numerical features
- **Neural Network (MLP)**: Multi-layer perceptron for complex pattern recognition

### Feature Engineering

#### Numerical Features (9 features)
1. **URL Length**: Total character count
2. **Hostname Length**: Domain name length
3. **Number of Dots**: Count of '.' in hostname
4. **Uses HTTPS**: Binary indicator (1/0)
5. **Has Suspicious Keywords**: Binary indicator for phishing-related terms
6. **Number of Dashes**: Count of '-' in hostname
7. **Has At Symbol**: Binary indicator for '@' presence
8. **Number of Query Components**: Count of URL parameters
9. **Domain Age**: Estimated domain age in days

#### Text Features (TF-IDF)
- URL text converted to TF-IDF vectors
- Combined with numerical features for Team 3 models

### Voting System

The final prediction uses a majority voting system:

1. Each model votes (0 = Legitimate, 1 = Phishing)
2. Votes are counted
3. Majority decision is taken
4. In case of tie, defaults to "Phishing" for safety

### Model Performance

The ensemble approach provides:
- **High Accuracy**: Multiple models reduce false positives/negatives
- **Robustness**: Different algorithms catch different patterns
- **Reliability**: Voting system provides consensus

---

## Database Schema

### ScanResult Table

| Field | Type | Description |
|-------|------|-------------|
| id | AutoField | Primary key |
| url | URLField(2000) | The scanned URL |
| result | CharField(20) | Classification result |
| timestamp | DateTimeField | Scan timestamp |

### Database Configuration

#### PostgreSQL (Production)
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'phish_guard_backend',
        'USER': 'postgres',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

#### SQLite (Development)
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
```

---

## Deployment Guide

### Production Deployment

#### Backend Deployment

1. **Environment Setup**
```bash
# Install production dependencies
pip install gunicorn psycopg2-binary

# Set environment variables
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

#### Frontend Deployment

1. **Build for Production**
```bash
npm run build
```

2. **Serve Static Files**
```bash
# Use nginx or serve with Django
python manage.py runserver --settings=production_settings
```

#### Browser Extension Deployment

1. **Package Extension**
   - Zip the `phish_guard_extension` folder
   - Upload to Chrome Web Store (if publishing)

2. **Update Manifest**
   - Change `host_permissions` to production URL
   - Update version number

### Docker Deployment (Optional)

#### Dockerfile for Backend
```dockerfile
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["gunicorn", "phish_guard_backend.wsgi:application", "--bind", "0.0.0.0:8000"]
```

#### Docker Compose
```yaml
version: '3.8'
services:
  db:
    image: postgres:13
    environment:
      POSTGRES_DB: phish_guard_backend
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  web:
    build: .
    command: python manage.py runserver 0.0.0.0:8000
    volumes:
      - .:/app
    ports:
      - "8000:8000"
    depends_on:
      - db

volumes:
  postgres_data:
```

---

## Testing

### Backend Testing

#### Unit Tests
```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test api

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

#### API Testing
```bash
# Test scan endpoint
curl -X POST http://localhost:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Test logs endpoint
curl http://localhost:8000/api/logs/
```

### Frontend Testing

#### Component Testing
```bash
# Install testing dependencies
npm install --save-dev @testing-library/react @testing-library/jest-dom

# Run tests
npm test
```

#### Manual Testing
1. Test backend connection
2. Test URL scanning
3. Test data visualization
4. Test responsive design

### Extension Testing

1. **Load extension in Chrome**
2. **Test on various websites**:
   - Legitimate sites (google.com, facebook.com)
   - Suspicious sites
   - Error handling

---

## Troubleshooting

### Common Issues

#### Backend Issues

**Problem**: Models not loading
```bash
# Check if model files exist
ls phish_guard_backend/api/ml_model/

# Check Python dependencies
pip list | grep -E "(scikit-learn|joblib|xgboost|lightgbm)"
```

**Problem**: Database connection error
```bash
# Check PostgreSQL service
sudo systemctl status postgresql

# Test connection
psql -h localhost -U postgres -d phish_guard_backend
```

**Problem**: CORS errors
```python
# Check CORS settings in settings.py
CORS_ALLOW_ALL_ORIGINS = True  # For development only
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
```

#### Frontend Issues

**Problem**: Cannot connect to backend
```bash
# Check if Django server is running
curl http://localhost:8000/api/health/

# Check CORS configuration
# Verify backend URL in frontend code
```

**Problem**: Build errors
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node.js version
node --version  # Should be 16+
```

#### Extension Issues

**Problem**: Extension not working
1. Check Chrome extension permissions
2. Verify manifest.json syntax
3. Check console for errors
4. Ensure backend is accessible

**Problem**: API requests failing
1. Check host_permissions in manifest.json
2. Verify backend URL
3. Check CORS settings

### Performance Optimization

#### Backend Optimization
- Use database indexing for frequently queried fields
- Implement caching for model predictions
- Use connection pooling for database
- Optimize feature extraction

#### Frontend Optimization
- Implement lazy loading for large datasets
- Use React.memo for component optimization
- Implement virtual scrolling for large tables
- Optimize bundle size

---

## Future Enhancements

### Planned Features

#### Backend Enhancements
1. **Model Updates**: Regular retraining with new data
2. **API Rate Limiting**: Prevent abuse
3. **Authentication**: User accounts and API keys
4. **Analytics**: Detailed usage statistics
5. **Batch Processing**: Multiple URL scanning

#### Frontend Enhancements
1. **User Dashboard**: Personal scan history
2. **Advanced Filtering**: Date ranges, result types
3. **Export Features**: CSV/JSON export
4. **Real-time Updates**: WebSocket integration
5. **Mobile App**: React Native version

#### Extension Enhancements
1. **Automatic Scanning**: Background URL checking
2. **Whitelist Management**: Trusted domains
3. **Notification System**: Alert for suspicious sites
4. **History Integration**: Scan history in extension
5. **Multi-browser Support**: Firefox, Safari versions

#### Machine Learning Enhancements
1. **Deep Learning Models**: CNN, RNN for URL analysis
2. **Feature Engineering**: More sophisticated features
3. **Ensemble Methods**: Advanced voting mechanisms
4. **Online Learning**: Continuous model updates
5. **Explainable AI**: Feature importance analysis

### Technical Improvements

#### Security
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- API authentication

#### Scalability
- Microservices architecture
- Load balancing
- Database sharding
- Caching layers
- CDN integration

#### Monitoring
- Application performance monitoring
- Error tracking and logging
- Health checks and alerts
- Usage analytics
- Performance metrics

---

## Conclusion

Phish-Guard is a comprehensive phishing detection system that combines multiple machine learning models with modern web technologies. The system provides real-time protection through a browser extension, comprehensive monitoring through a web dashboard, and flexible integration through a RESTful API.

The modular architecture allows for easy maintenance and future enhancements, while the ensemble machine learning approach ensures high accuracy and reliability in phishing detection.

For support, questions, or contributions, please refer to the project repository or contact the development team.

---

**Last Updated**: January 2024  
**Version**: 1.0.0  
**License**: MIT License
