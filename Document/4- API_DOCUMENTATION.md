# 🔌 Phish-Guard API Documentation

Complete API reference for the Phish-Guard phishing detection system.

## 📋 Table of Contents

1. [Base URL](#base-url)
2. [Authentication](#authentication)
3. [Endpoints](#endpoints)
4. [Data Models](#data-models)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Examples](#examples)
8. [SDK Examples](#sdk-examples)

---

## Base URL

```
Development: http://127.0.0.1:8000
Production: https://your-domain.com
```

---

## Authentication

Currently, the API does not require authentication. All endpoints are publicly accessible.

**Future Enhancement**: API key authentication will be added in future versions.

---

## Endpoints

### 1. Scan URL

Scans a URL for phishing detection using multiple machine learning models.

#### Request

```http
POST /api/scan/
Content-Type: application/json
```

#### Request Body

```json
{
    "url": "https://example.com"
}
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| url | string | Yes | The URL to scan (must be valid URL format) |

#### Response

**Success (201 Created)**

```json
{
    "id": 1,
    "url": "https://example.com",
    "result": "Legitimate",
    "timestamp": "2024-01-15T10:30:00.123456Z",
    "processing_time": 0.245,
    "status": "success"
}
```

**Error (400 Bad Request)**

```json
{
    "status": "error",
    "message": "Invalid request data",
    "errors": {
        "url": ["This field is required."]
    }
}
```

**Error (500 Internal Server Error)**

```json
{
    "status": "error",
    "message": "Internal server error",
    "error": "Model loading failed"
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| id | integer | Unique identifier for the scan result |
| url | string | The scanned URL |
| result | string | Classification result ("Phishing" or "Legitimate") |
| timestamp | string | ISO 8601 timestamp of when scan was performed |
| processing_time | float | Time taken for prediction in seconds |
| status | string | Request status ("success" or "error") |

---

### 2. Get Scan Logs

Retrieves paginated list of scan results.

#### Request

```http
GET /api/logs/
```

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| page_size | integer | 20 | Number of results per page |
| search | string | - | Search in URL and result fields |
| ordering | string | -timestamp | Sort order (timestamp, url, result) |
| result | string | - | Filter by result type |

#### Response

**Success (200 OK)**

```json
{
    "count": 150,
    "next": "http://127.0.0.1:8000/api/logs/?page=2",
    "previous": null,
    "results": [
        {
            "id": 1,
            "url": "https://example.com",
            "result": "Legitimate",
            "timestamp": "2024-01-15T10:30:00.123456Z"
        },
        {
            "id": 2,
            "url": "https://suspicious-site.com",
            "result": "Phishing",
            "timestamp": "2024-01-15T10:25:00.123456Z"
        }
    ]
}
```

#### Example Requests

```bash
# Get first page
curl "http://127.0.0.1:8000/api/logs/"

# Get page 2 with 10 results per page
curl "http://127.0.0.1:8000/api/logs/?page=2&page_size=10"

# Search for specific URL
curl "http://127.0.0.1:8000/api/logs/?search=google"

# Filter by phishing results only
curl "http://127.0.0.1:8000/api/logs/?result=Phishing"

# Sort by URL alphabetically
curl "http://127.0.0.1:8000/api/logs/?ordering=url"
```

---

### 3. Models Status

Returns the status of all machine learning models.

#### Request

```http
GET /api/models/status/
```

#### Response

**Success (200 OK)**

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

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| status | string | Request status |
| models_loaded | string | Number of loaded models vs total |
| models_status | object | Detailed status of each model by team |
| all_models_ready | boolean | Whether all models are loaded and ready |

---

### 4. Health Check

Returns the health status of the API service.

#### Request

```http
GET /api/health/
```

#### Response

**Success (200 OK)**

```json
{
    "status": "healthy",
    "service": "Phishing Guard Backend",
    "version": "1.0.0",
    "cors_enabled": true,
    "api_endpoints": {
        "scan": "/api/scan/",
        "logs": "/api/logs/",
        "scan_logs": "/api/scan-logs/",
        "models_status": "/api/models/status/",
        "health": "/api/health/"
    }
}
```

---

### 5. Connection Test

Tests the connection from frontend applications.

#### Request

```http
GET /api/connection-test/
POST /api/connection-test/
OPTIONS /api/connection-test/
```

#### Response

**Success (200 OK)**

```json
{
    "status": "connected",
    "message": "Backend connection successful",
    "timestamp": 1705312200.123,
    "method": "GET",
    "headers": {
        "Host": "127.0.0.1:8000",
        "User-Agent": "Mozilla/5.0...",
        "Accept": "application/json"
    },
    "cors_working": true
}
```

---

## Data Models

### ScanResult

Represents a URL scan result in the database.

```json
{
    "id": 1,
    "url": "https://example.com",
    "result": "Legitimate",
    "timestamp": "2024-01-15T10:30:00.123456Z"
}
```

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| id | integer | Primary key (auto-generated) |
| url | string | The scanned URL (max 2000 characters) |
| result | string | Classification result ("Phishing" or "Legitimate") |
| timestamp | string | ISO 8601 timestamp (auto-generated) |

---

## Error Handling

The API uses standard HTTP status codes and returns JSON error responses.

### Status Codes

| Code | Description |
|------|-------------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid request data |
| 404 | Not Found - Resource not found |
| 500 | Internal Server Error - Server error |

### Error Response Format

```json
{
    "status": "error",
    "message": "Human-readable error message",
    "errors": {
        "field_name": ["Detailed error message"]
    }
}
```

### Common Errors

#### Invalid URL Format
```json
{
    "status": "error",
    "message": "Invalid request data",
    "errors": {
        "url": ["Enter a valid URL."]
    }
}
```

#### Missing Required Field
```json
{
    "status": "error",
    "message": "Invalid request data",
    "errors": {
        "url": ["This field is required."]
    }
}
```

#### Model Loading Error
```json
{
    "status": "error",
    "message": "Internal server error",
    "error": "Error loading model: Random Forest"
}
```

---

## Rate Limiting

Currently, there are no rate limits implemented. This will be added in future versions.

**Future Enhancement**: Rate limiting will be implemented to prevent abuse.

---

## Examples

### JavaScript (Fetch API)

```javascript
// Scan a URL
async function scanUrl(url) {
    try {
        const response = await fetch('http://127.0.0.1:8000/api/scan/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log('Scan result:', data.result);
            return data;
        } else {
            console.error('Error:', data.message);
            throw new Error(data.message);
        }
    } catch (error) {
        console.error('Network error:', error);
        throw error;
    }
}

// Get scan logs
async function getScanLogs(page = 1, pageSize = 20) {
    try {
        const response = await fetch(
            `http://127.0.0.1:8000/api/logs/?page=${page}&page_size=${pageSize}`
        );
        
        const data = await response.json();
        return data.results;
    } catch (error) {
        console.error('Error fetching logs:', error);
        throw error;
    }
}

// Usage
scanUrl('https://www.google.com')
    .then(result => console.log('Result:', result))
    .catch(error => console.error('Error:', error));
```

### Python (requests)

```python
import requests
import json

# Scan a URL
def scan_url(url):
    try:
        response = requests.post(
            'http://127.0.0.1:8000/api/scan/',
            json={'url': url},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 201:
            return response.json()
        else:
            error_data = response.json()
            raise Exception(f"Error: {error_data.get('message', 'Unknown error')}")
            
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error: {e}")

# Get scan logs
def get_scan_logs(page=1, page_size=20):
    try:
        response = requests.get(
            f'http://127.0.0.1:8000/api/logs/',
            params={'page': page, 'page_size': page_size}
        )
        
        if response.status_code == 200:
            return response.json()['results']
        else:
            raise Exception(f"Error: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error: {e}")

# Usage
try:
    result = scan_url('https://www.google.com')
    print(f"Scan result: {result['result']}")
    
    logs = get_scan_logs()
    print(f"Found {len(logs)} scan logs")
    
except Exception as e:
    print(f"Error: {e}")
```

### cURL Examples

```bash
# Scan a URL
curl -X POST http://127.0.0.1:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

# Get scan logs
curl http://127.0.0.1:8000/api/logs/

# Get specific page
curl "http://127.0.0.1:8000/api/logs/?page=2&page_size=10"

# Search logs
curl "http://127.0.0.1:8000/api/logs/?search=google"

# Filter by result
curl "http://127.0.0.1:8000/api/logs/?result=Phishing"

# Check models status
curl http://127.0.0.1:8000/api/models/status/

# Health check
curl http://127.0.0.1:8000/api/health/
```

---

## SDK Examples

### Node.js SDK

```javascript
class PhishGuardAPI {
    constructor(baseURL = 'http://127.0.0.1:8000') {
        this.baseURL = baseURL;
    }
    
    async scanUrl(url) {
        const response = await fetch(`${this.baseURL}/api/scan/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message);
        }
        
        return response.json();
    }
    
    async getLogs(options = {}) {
        const params = new URLSearchParams();
        if (options.page) params.append('page', options.page);
        if (options.pageSize) params.append('page_size', options.pageSize);
        if (options.search) params.append('search', options.search);
        if (options.result) params.append('result', options.result);
        
        const response = await fetch(`${this.baseURL}/api/logs/?${params}`);
        return response.json();
    }
    
    async getModelsStatus() {
        const response = await fetch(`${this.baseURL}/api/models/status/`);
        return response.json();
    }
    
    async healthCheck() {
        const response = await fetch(`${this.baseURL}/api/health/`);
        return response.json();
    }
}

// Usage
const api = new PhishGuardAPI();

api.scanUrl('https://www.google.com')
    .then(result => console.log('Result:', result))
    .catch(error => console.error('Error:', error));
```

### Python SDK

```python
import requests
from typing import Dict, List, Optional

class PhishGuardAPI:
    def __init__(self, base_url: str = 'http://127.0.0.1:8000'):
        self.base_url = base_url
        self.session = requests.Session()
    
    def scan_url(self, url: str) -> Dict:
        """Scan a URL for phishing detection."""
        response = self.session.post(
            f'{self.base_url}/api/scan/',
            json={'url': url}
        )
        
        if response.status_code == 201:
            return response.json()
        else:
            error_data = response.json()
            raise Exception(error_data.get('message', 'Unknown error'))
    
    def get_logs(self, page: int = 1, page_size: int = 20, 
                 search: Optional[str] = None, 
                 result: Optional[str] = None) -> Dict:
        """Get paginated scan logs."""
        params = {'page': page, 'page_size': page_size}
        if search:
            params['search'] = search
        if result:
            params['result'] = result
        
        response = self.session.get(f'{self.base_url}/api/logs/', params=params)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Error: {response.status_code}")
    
    def get_models_status(self) -> Dict:
        """Get machine learning models status."""
        response = self.session.get(f'{self.base_url}/api/models/status/')
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Error: {response.status_code}")
    
    def health_check(self) -> Dict:
        """Check API health."""
        response = self.session.get(f'{self.base_url}/api/health/')
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Error: {response.status_code}")

# Usage
api = PhishGuardAPI()

try:
    result = api.scan_url('https://www.google.com')
    print(f"Scan result: {result['result']}")
    
    logs = api.get_logs(page=1, page_size=10)
    print(f"Found {len(logs['results'])} logs")
    
except Exception as e:
    print(f"Error: {e}")
```

---

## Testing

### Manual Testing

```bash
# Test all endpoints
curl http://127.0.0.1:8000/api/health/
curl http://127.0.0.1:8000/api/models/status/
curl -X POST http://127.0.0.1:8000/api/scan/ -H "Content-Type: application/json" -d '{"url": "https://www.google.com"}'
curl http://127.0.0.1:8000/api/logs/
```

### Automated Testing

```python
import unittest
import requests

class TestPhishGuardAPI(unittest.TestCase):
    def setUp(self):
        self.base_url = 'http://127.0.0.1:8000'
    
    def test_health_check(self):
        response = requests.get(f'{self.base_url}/api/health/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'healthy')
    
    def test_scan_url(self):
        response = requests.post(
            f'{self.base_url}/api/scan/',
            json={'url': 'https://www.google.com'}
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn('result', data)
        self.assertIn(data['result'], ['Phishing', 'Legitimate'])
    
    def test_get_logs(self):
        response = requests.get(f'{self.base_url}/api/logs/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('results', data)
        self.assertIn('count', data)

if __name__ == '__main__':
    unittest.main()
```

---

## Changelog

### Version 1.0.0
- Initial API release
- URL scanning endpoint
- Scan logs retrieval
- Models status endpoint
- Health check endpoint
- Connection test endpoint

---

## Support

For API support and questions:
- Check the troubleshooting section
- Review the complete project documentation
- Contact the development team

---

**API Documentation Version**: 1.0.0  
**Last Updated**: January 2024
