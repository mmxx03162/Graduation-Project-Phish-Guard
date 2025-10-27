# 🚀 Phish-Guard Setup Guide

This guide will help you set up the Phish-Guard phishing detection system from scratch.

## 📋 Prerequisites

Before starting, ensure you have the following installed:

- **Python 3.13+** - [Download here](https://python.org/downloads/)
- **Node.js 16+** - [Download here](https://nodejs.org/)
- **PostgreSQL 12+** (optional) - [Download here](https://postgresql.org/download/)
- **Git** - [Download here](https://git-scm.com/downloads)

## 🔧 Installation Steps

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone <your-repository-url>
cd phish-guard-project
```

### Step 2: Backend Setup

```bash
# Navigate to backend directory
cd phish_guard_backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser

# Start Django development server
python manage.py runserver
```

The backend will be available at: `http://127.0.0.1:8000`

### Step 3: Frontend Setup

Open a new terminal window:

```bash
# Navigate to frontend directory
cd "Front end/phish-guard-dashboard"

# Install Node.js dependencies
npm install

# Start React development server
npm run dev
```

The frontend will be available at: `http://localhost:5173`

### Step 4: Browser Extension Setup

1. **Open Chrome Browser**
2. **Navigate to Extensions**
   - Go to `chrome://extensions/`
   - Or click Chrome menu → More tools → Extensions

3. **Enable Developer Mode**
   - Toggle "Developer mode" in the top right

4. **Load Extension**
   - Click "Load unpacked"
   - Select the `phish_guard_extension` folder
   - The Phish-Guard extension should appear in your extensions

5. **Pin Extension** (optional)
   - Click the puzzle piece icon in Chrome toolbar
   - Pin the Phish-Guard extension for easy access

## 🧪 Testing the Installation

### Test Backend API

```bash
# Health check
curl http://127.0.0.1:8000/api/health/

# Test URL scanning
curl -X POST http://127.0.0.1:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

### Test Frontend Dashboard

1. Open `http://localhost:5173` in your browser
2. You should see the Phish-Guard Dashboard
3. Check that the backend connection status shows "🟢 Backend Connected"
4. Try refreshing the data

### Test Browser Extension

1. Visit any website (e.g., `https://www.google.com`)
2. Click the Phish-Guard extension icon
3. Click "Check Current Site"
4. You should see a result (Legitimate/Phishing)

## 🔧 Configuration

### Database Configuration

#### Option 1: SQLite (Default - Easy Setup)
No additional configuration needed. SQLite will be used automatically.

#### Option 2: PostgreSQL (Recommended for Production)

1. **Install PostgreSQL**
2. **Create Database**
```sql
CREATE DATABASE phish_guard_backend;
CREATE USER phish_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE phish_guard_backend TO phish_user;
```

3. **Update Settings**
Edit `phish_guard_backend/phish_guard_backend/settings.py`:
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'phish_guard_backend',
        'USER': 'phish_user',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

4. **Run Migrations**
```bash
python manage.py migrate
```

### CORS Configuration

If you're running the frontend on a different port, update CORS settings in `settings.py`:

```python
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # React default
    "http://localhost:5173",  # Vite default
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]
```

## 🚀 Running the Application

### Development Mode

1. **Start Backend** (Terminal 1)
```bash
cd phish_guard_backend
source venv/bin/activate  # or venv\Scripts\activate on Windows
python manage.py runserver
```

2. **Start Frontend** (Terminal 2)
```bash
cd "Front end/phish-guard-dashboard"
npm run dev
```

3. **Load Extension** (One-time setup)
- Follow Step 4 above

### Production Mode

1. **Build Frontend**
```bash
cd "Front end/phish-guard-dashboard"
npm run build
```

2. **Start Backend with Gunicorn**
```bash
cd phish_guard_backend
pip install gunicorn
gunicorn phish_guard_backend.wsgi:application --bind 0.0.0.0:8000
```

## 🐛 Troubleshooting

### Common Issues

#### Backend Issues

**Problem**: `ModuleNotFoundError` for ML libraries
```bash
# Solution: Install missing dependencies
pip install scikit-learn joblib xgboost lightgbm pandas numpy scipy
```

**Problem**: Database connection error
```bash
# Solution: Check database settings
python manage.py check --database default
```

**Problem**: Models not loading
```bash
# Solution: Check if model files exist
ls phish_guard_backend/api/ml_model/
```

#### Frontend Issues

**Problem**: Cannot connect to backend
```bash
# Solution: Check if Django server is running
curl http://127.0.0.1:8000/api/health/
```

**Problem**: CORS errors
```bash
# Solution: Update CORS settings in settings.py
CORS_ALLOW_ALL_ORIGINS = True  # For development only
```

#### Extension Issues

**Problem**: Extension not working
- Check Chrome extension permissions
- Verify manifest.json syntax
- Ensure backend is accessible from extension

**Problem**: API requests failing
- Check `host_permissions` in manifest.json
- Verify backend URL in popup.js

### Performance Issues

**Slow predictions**:
- Check if all models are loaded
- Monitor system resources
- Consider model optimization

**High memory usage**:
- Models require ~500MB RAM
- Consider using fewer models for development

## 📊 Verification Checklist

- [ ] Python 3.13+ installed
- [ ] Node.js 16+ installed
- [ ] Repository cloned
- [ ] Virtual environment created and activated
- [ ] Backend dependencies installed
- [ ] Database migrations completed
- [ ] Django server running on port 8000
- [ ] Frontend dependencies installed
- [ ] React server running on port 5173
- [ ] Browser extension loaded
- [ ] API health check successful
- [ ] Frontend shows "Backend Connected"
- [ ] Extension can scan URLs
- [ ] All components working together

## 🎯 Next Steps

After successful installation:

1. **Explore the Dashboard**: Visit the React dashboard to see scan results
2. **Test the Extension**: Try scanning different websites
3. **Check API Documentation**: Review available endpoints
4. **Read Full Documentation**: Check `PROJECT_DOCUMENTATION.md`
5. **Customize Settings**: Modify configuration as needed

## 📞 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the complete documentation
3. Check the project's issue tracker
4. Contact the development team

## 🎉 Congratulations!

You have successfully set up Phish-Guard! The system is now ready to detect phishing websites using advanced machine learning models.

---

**Happy Phishing Detection! 🛡️**
