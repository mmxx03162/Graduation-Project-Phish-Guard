# 🔧 Phish-Guard Code Examples & Patterns Guide
## Practical Code Examples and Implementation Patterns

---

## Table of Contents
1. [Critical Code Snippets](#critical-code-snippets)
2. [API Integration Examples](#api-integration-examples)
3. [Error Handling Patterns](#error-handling-patterns)
4. [Performance Optimization Examples](#performance-optimization-examples)
5. [Testing Code Examples](#testing-code-examples)
6. [Deployment Code Examples](#deployment-code-examples)

---

## Critical Code Snippets

### 1. Machine Learning Prediction Core

```python
# CRITICAL: Main prediction function - The heart of the system
def make_prediction(url: str) -> str:
    """
    This function orchestrates the entire ML prediction process.
    It's the most critical function in the system.
    """
    # Step 1: Validate URL format
    if not validate_url(url):
        return "Error: Invalid URL format"
    
    all_votes = []  # Store votes from all 6 models
    
    # Step 2: Extract features for each team
    # Team 1: Numerical features
    extractor_t1 = PhishingFeatureExtractor()
    team1_df = extractor_t1.get_feature_dataframe(url)
    
    # Team 2: Scaled numerical features
    team2_features = extract_team2_features(url)
    team2_df = pd.DataFrame([team2_features], columns=TEAM2_COLUMNS)
    scaled_features = scaler_team2.transform(team2_df)
    
    # Team 3: Combined features
    text_features = vectorizer_team3.transform([url.lower()])
    numerical_features = extract_numerical_features(url)
    combined_features = hstack([text_features, numerical_features])
    
    # Step 3: Get predictions from all models
    # Team 1 Models
    if model_1_1_rf:
        pred = predict_with_threshold(model_1_1_rf, team1_df, threshold_1_1, "Random Forest")
        if pred is not None:
            all_votes.append(pred)
    
    if model_1_2_lgbm:
        pred = predict_with_threshold(model_1_2_lgbm, team1_df, threshold_1_2, "LightGBM")
        if pred is not None:
            all_votes.append(pred)
    
    # Team 2 Models
    if model_2_1_lr:
        pred = predict_with_threshold(model_2_1_lr, scaled_features, threshold_2_1, "Logistic Regression")
        if pred is not None:
            all_votes.append(pred)
    
    if model_2_2_svc:
        pred = predict_with_threshold(model_2_2_svc, scaled_features, threshold_2_2, "SVC")
        if pred is not None:
            all_votes.append(pred)
    
    # Team 3 Models
    if model_3_1_xgb:
        pred = predict_with_threshold(model_3_1_xgb, combined_features, threshold_3_1, "XGBoost")
        if pred is not None:
            all_votes.append(pred)
    
    if model_3_2_mlp:
        pred = predict_with_threshold(model_3_2_mlp, combined_features, threshold_3_2, "Neural Network")
        if pred is not None:
            all_votes.append(pred)
    
    # Step 4: Majority voting
    if not all_votes:
        return "Error: No models available"
    
    vote_counts = Counter(all_votes)
    phishing_votes = vote_counts.get(1, 0)
    legitimate_votes = vote_counts.get(0, 0)
    
    # Final decision: majority wins, tie defaults to phishing for safety
    if phishing_votes > legitimate_votes:
        return "Phishing"
    elif legitimate_votes > phishing_votes:
        return "Legitimate"
    else:
        return "Phishing"  # Tie-breaker for safety
```

### 2. Feature Extraction Engine

```python
# CRITICAL: Feature extraction for Team 1
class PhishingFeatureExtractor:
    def extract_features(self, url):
        """
        Extract 9 critical features from URL.
        These features must match the training dataset exactly.
        """
        features = {}
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Feature 1: URL Length
        features['URLURL_Length'] = len(url)
        
        # Feature 2: At Symbol Presence
        features['having_At_Symbol'] = 1 if '@' in url else -1
        
        # Feature 3: Dash in Domain
        features['Prefix_Suffix'] = 1 if '-' in domain else -1
        
        # Feature 4: Subdomain Count
        dot_count = domain.count('.')
        if dot_count == 0:
            features['having_Sub_Domain'] = 1
        elif dot_count == 1:
            features['having_Sub_Domain'] = -1
        elif dot_count == 2:
            features['having_Sub_Domain'] = 0
        else:
            features['having_Sub_Domain'] = 1
        
        # Feature 5: SSL Certificate Status
        features['SSLfinal_State'] = self._check_ssl(url)
        
        # Feature 6: Domain Registration Length (estimated)
        features['Domain_registeration_length'] = self._estimate_domain_registration(domain)
        
        # Feature 7: Domain Age (estimated)
        features['age_of_domain'] = self._estimate_domain_age(domain)
        
        # Feature 8: DNS Record Existence
        features['DNSRecord'] = self._check_dns(domain)
        
        # Feature 9: Page Rank (estimated)
        features['Page_Rank'] = self._estimate_page_rank(domain)
        
        return features
    
    def _check_ssl(self, url):
        """CRITICAL: Real SSL certificate verification"""
        try:
            if url.startswith('https://'):
                parsed = urlparse(url)
                domain = parsed.netloc
                
                # Perform actual SSL handshake
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        return -1  # Valid SSL
            else:
                return 1  # No HTTPS
        except:
            return 0  # Invalid SSL
```

### 3. API Endpoint Implementation

```python
# CRITICAL: Main API endpoint for URL scanning
@csrf_exempt
@api_view(['POST'])
def scan_url_view(request):
    """
    This is the main API endpoint that handles all URL scanning requests.
    It's critical for the entire system functionality.
    """
    start_time = time.time()  # Performance monitoring
    
    try:
        # Step 1: Validate input data
        serializer = ScanResultSerializer(data=request.data)
        
        if not serializer.is_valid():
            logger.warning(f"Invalid request data: {serializer.errors}")
            return Response({
                'status': 'error',
                'message': 'Invalid request data',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Step 2: Extract URL and make prediction
        url_to_check = serializer.validated_data['url']
        logger.info(f"Analyzing URL: {url_to_check}")
        
        prediction_result = make_prediction(url_to_check)
        
        # Step 3: Calculate processing time
        processing_time = time.time() - start_time
        
        # Step 4: Save result to database
        scan_result = serializer.save(result=prediction_result)
        
        # Step 5: Return comprehensive response
        response_data = {
            'id': scan_result.id,
            'url': scan_result.url,
            'result': scan_result.result,
            'timestamp': scan_result.timestamp,
            'processing_time': round(processing_time, 3),
            'status': 'success'
        }
        
        logger.info(f"Prediction completed: {prediction_result} (Time: {processing_time:.3f}s)")
        
        return Response(response_data, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
```

---

## API Integration Examples

### 1. JavaScript Frontend Integration

```javascript
// CRITICAL: Frontend API integration with comprehensive error handling
class PhishGuardAPI {
    constructor(baseURL = 'http://127.0.0.1:8000') {
        this.baseURL = baseURL;
    }
    
    async scanUrl(url) {
        try {
            const response = await fetch(`${this.baseURL}/api/scan/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body: JSON.stringify({ url: url }),
                mode: 'cors',
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP ${response.status}`);
            }
            
            const data = await response.json();
            return data;
            
        } catch (error) {
            console.error('Scan URL error:', error);
            throw error;
        }
    }
    
    async getScanLogs(page = 1, pageSize = 20, filters = {}) {
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                page_size: pageSize.toString(),
            });
            
            // Add filters if provided
            if (filters.search) params.append('search', filters.search);
            if (filters.result) params.append('result', filters.result);
            if (filters.dateFrom) params.append('date_from', filters.dateFrom);
            if (filters.dateTo) params.append('date_to', filters.dateTo);
            
            const response = await fetch(`${this.baseURL}/api/logs/?${params}`);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            return await response.json();
            
        } catch (error) {
            console.error('Get scan logs error:', error);
            throw error;
        }
    }
    
    async checkModelsStatus() {
        try {
            const response = await fetch(`${this.baseURL}/api/models/status/`);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            return await response.json();
            
        } catch (error) {
            console.error('Check models status error:', error);
            throw error;
        }
    }
}

// Usage example
const api = new PhishGuardAPI();

// Scan a URL
api.scanUrl('https://www.google.com')
    .then(result => {
        console.log('Scan result:', result.result);
        console.log('Processing time:', result.processing_time);
    })
    .catch(error => {
        console.error('Error:', error.message);
    });

// Get scan logs with filters
api.getScanLogs(1, 20, { result: 'Phishing' })
    .then(data => {
        console.log('Phishing sites:', data.results);
    })
    .catch(error => {
        console.error('Error:', error.message);
    });
```

### 2. Python SDK Integration

```python
# CRITICAL: Python SDK for API integration
import requests
import json
from typing import Dict, List, Optional

class PhishGuardSDK:
    def __init__(self, base_url: str = 'http://127.0.0.1:8000'):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })
    
    def scan_url(self, url: str) -> Dict:
        """
        Scan a URL for phishing detection.
        
        Args:
            url (str): The URL to scan
            
        Returns:
            Dict: Scan result with metadata
            
        Raises:
            Exception: If scan fails
        """
        try:
            response = self.session.post(
                f'{self.base_url}/api/scan/',
                json={'url': url},
                timeout=30
            )
            
            if response.status_code == 201:
                return response.json()
            else:
                error_data = response.json()
                raise Exception(error_data.get('message', 'Unknown error'))
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {e}")
    
    def get_scan_logs(self, page: int = 1, page_size: int = 20, 
                     search: Optional[str] = None,
                     result: Optional[str] = None,
                     date_from: Optional[str] = None,
                     date_to: Optional[str] = None) -> Dict:
        """
        Get paginated scan logs with optional filtering.
        
        Args:
            page (int): Page number
            page_size (int): Number of results per page
            search (str): Search term for URLs
            result (str): Filter by result type
            date_from (str): Start date filter
            date_to (str): End date filter
            
        Returns:
            Dict: Paginated scan logs
        """
        params = {
            'page': page,
            'page_size': page_size,
        }
        
        if search:
            params['search'] = search
        if result:
            params['result'] = result
        if date_from:
            params['date_from'] = date_from
        if date_to:
            params['date_to'] = date_to
        
        try:
            response = self.session.get(
                f'{self.base_url}/api/logs/',
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"HTTP {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {e}")
    
    def get_models_status(self) -> Dict:
        """Get machine learning models status."""
        try:
            response = self.session.get(
                f'{self.base_url}/api/models/status/',
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"HTTP {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {e}")
    
    def health_check(self) -> Dict:
        """Check API health status."""
        try:
            response = self.session.get(
                f'{self.base_url}/api/health/',
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"HTTP {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {e}")

# Usage example
if __name__ == "__main__":
    sdk = PhishGuardSDK()
    
    try:
        # Health check
        health = sdk.health_check()
        print(f"API Status: {health['status']}")
        
        # Scan a URL
        result = sdk.scan_url('https://www.google.com')
        print(f"Scan Result: {result['result']}")
        print(f"Processing Time: {result['processing_time']}s")
        
        # Get recent scan logs
        logs = sdk.get_scan_logs(page_size=10)
        print(f"Recent scans: {len(logs['results'])}")
        
        # Check models status
        models_status = sdk.get_models_status()
        print(f"Models loaded: {models_status['models_loaded']}")
        
    except Exception as e:
        print(f"Error: {e}")
```

---

## Error Handling Patterns

### 1. Backend Error Handling

```python
# CRITICAL: Comprehensive error handling pattern
import logging
from rest_framework import status
from rest_framework.response import Response

logger = logging.getLogger(__name__)

def handle_api_request(func):
    """
    Decorator for consistent API error handling.
    This pattern ensures all API endpoints handle errors consistently.
    """
    def wrapper(request, *args, **kwargs):
        try:
            return func(request, *args, **kwargs)
        except ValidationError as e:
            logger.warning(f"Validation error in {func.__name__}: {e}")
            return Response({
                'status': 'error',
                'message': 'Invalid request data',
                'errors': e.detail if hasattr(e, 'detail') else str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except PermissionError as e:
            logger.warning(f"Permission error in {func.__name__}: {e}")
            return Response({
                'status': 'error',
                'message': 'Permission denied',
                'error': str(e)
            }, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            return Response({
                'status': 'error',
                'message': 'Internal server error',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return wrapper

# Usage example
@handle_api_request
@api_view(['POST'])
def scan_url_view(request):
    # Main logic here
    pass
```

### 2. Frontend Error Handling

```javascript
// CRITICAL: Frontend error handling with user feedback
class ErrorHandler {
    static handleApiError(error, context = '') {
        let errorMessage = 'An unexpected error occurred';
        
        if (error.name === 'AbortError') {
            errorMessage = 'Request timeout - Please try again';
        } else if (error.message.includes('Failed to fetch')) {
            errorMessage = 'Cannot connect to server - Check your connection';
        } else if (error.message.includes('HTTP 400')) {
            errorMessage = 'Invalid request - Please check your input';
        } else if (error.message.includes('HTTP 500')) {
            errorMessage = 'Server error - Please try again later';
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        console.error(`Error in ${context}:`, error);
        
        // Show user-friendly error message
        this.showErrorNotification(errorMessage);
        
        return errorMessage;
    }
    
    static showErrorNotification(message) {
        // Implementation for showing error notifications
        // This could be a toast, modal, or inline message
        console.error('User Error:', message);
    }
}

// Usage example
async function scanUrl(url) {
    try {
        const response = await fetch('/api/scan/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        return await response.json();
        
    } catch (error) {
        ErrorHandler.handleApiError(error, 'scanUrl');
        throw error;
    }
}
```

---

## Performance Optimization Examples

### 1. Database Query Optimization

```python
# CRITICAL: Optimized database queries
from django.db import models
from django.db.models import Q, Count, Avg

class OptimizedScanLogView(generics.ListAPIView):
    """
    Optimized view with efficient database queries.
    """
    serializer_class = ScanResultSerializer
    pagination_class = ScanResultPagination
    
    def get_queryset(self):
        """
        Optimized queryset with efficient filtering and ordering.
        """
        # Base queryset with efficient ordering
        queryset = ScanResult.objects.all().order_by('-timestamp')
        
        # Efficient filtering using database-level operations
        filters = Q()
        
        # Date range filtering
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        
        if date_from:
            filters &= Q(timestamp__date__gte=date_from)
        if date_to:
            filters &= Q(timestamp__date__lte=date_to)
        
        # Result type filtering
        result_filter = self.request.query_params.get('result')
        if result_filter:
            filters &= Q(result=result_filter)
        
        # URL search filtering
        search_term = self.request.query_params.get('search')
        if search_term:
            filters &= Q(url__icontains=search_term)
        
        # Apply all filters at once
        if filters:
            queryset = queryset.filter(filters)
        
        return queryset
    
    def get_serializer_context(self):
        """
        Add additional context for serialization.
        """
        context = super().get_serializer_context()
        context['request'] = self.request
        return context
```

### 2. Frontend Performance Optimization

```javascript
// CRITICAL: Frontend performance optimization
import React, { useState, useEffect, useMemo, useCallback } from 'react';

const OptimizedScanLogTable = React.memo(({ scans = [] }) => {
    // State management
    const [sortField, setSortField] = useState('timestamp');
    const [sortOrder, setSortOrder] = useState('desc');
    const [filterResult, setFilterResult] = useState('all');
    
    // CRITICAL: Memoize expensive sorting operation
    const sortedScans = useMemo(() => {
        return [...scans].sort((a, b) => {
            let aValue = a[sortField];
            let bValue = b[sortField];
            
            if (sortField === 'timestamp') {
                aValue = new Date(aValue);
                bValue = new Date(bValue);
            }
            
            if (sortOrder === 'asc') {
                return aValue > bValue ? 1 : -1;
            } else {
                return aValue < bValue ? 1 : -1;
            }
        });
    }, [scans, sortField, sortOrder]);
    
    // CRITICAL: Memoize filtering operation
    const filteredScans = useMemo(() => {
        if (filterResult === 'all') return sortedScans;
        return sortedScans.filter(scan => scan.result === filterResult);
    }, [sortedScans, filterResult]);
    
    // CRITICAL: Memoize event handlers to prevent unnecessary re-renders
    const handleSort = useCallback((field) => {
        if (sortField === field) {
            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
        } else {
            setSortField(field);
            setSortOrder('desc');
        }
    }, [sortField, sortOrder]);
    
    const handleFilterChange = useCallback((value) => {
        setFilterResult(value);
    }, []);
    
    // CRITICAL: Memoize statistics calculation
    const stats = useMemo(() => {
        return {
            total: scans.length,
            phishing: scans.filter(s => s.result === 'Phishing').length,
            legitimate: scans.filter(s => s.result === 'Legitimate').length,
        };
    }, [scans]);
    
    return (
        <div className="table-container">
            {/* Table controls */}
            <div className="table-controls">
                <select 
                    value={filterResult} 
                    onChange={(e) => handleFilterChange(e.target.value)}
                >
                    <option value="all">All Results</option>
                    <option value="Phishing">Phishing Sites</option>
                    <option value="Legitimate">Legitimate Sites</option>
                </select>
                <div className="table-info">
                    Showing {filteredScans.length} of {scans.length} records
                </div>
            </div>
            
            {/* Table content */}
            <div className="table-wrapper">
                <table className="scan-table">
                    <thead>
                        <tr>
                            <th onClick={() => handleSort('url')}>
                                URL {sortField === 'url' && (sortOrder === 'asc' ? '↑' : '↓')}
                            </th>
                            <th onClick={() => handleSort('result')}>
                                Result {sortField === 'result' && (sortOrder === 'asc' ? '↑' : '↓')}
                            </th>
                            <th onClick={() => handleSort('timestamp')}>
                                Time {sortField === 'timestamp' && (sortOrder === 'asc' ? '↑' : '↓')}
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredScans.map(scan => (
                            <tr key={scan.id}>
                                <td>{scan.url}</td>
                                <td>{scan.result}</td>
                                <td>{new Date(scan.timestamp).toLocaleString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
});

export default OptimizedScanLogTable;
```

---

## Testing Code Examples

### 1. Backend Testing

```python
# CRITICAL: Comprehensive backend testing
import unittest
from django.test import TestCase, Client
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from api.models import ScanResult
from api.predictor import make_prediction, validate_url

class ScanResultModelTest(TestCase):
    """Test ScanResult model functionality."""
    
    def setUp(self):
        self.scan_result = ScanResult.objects.create(
            url='https://www.google.com',
            result='Legitimate'
        )
    
    def test_scan_result_creation(self):
        """Test scan result creation."""
        self.assertEqual(self.scan_result.url, 'https://www.google.com')
        self.assertEqual(self.scan_result.result, 'Legitimate')
        self.assertIsNotNone(self.scan_result.timestamp)
    
    def test_scan_result_str(self):
        """Test string representation."""
        self.assertEqual(str(self.scan_result), 'https://www.google.com')
    
    def test_is_phishing(self):
        """Test phishing detection method."""
        phishing_result = ScanResult.objects.create(
            url='https://suspicious-site.com',
            result='Phishing'
        )
        self.assertTrue(phishing_result.is_phishing())
        self.assertFalse(self.scan_result.is_phishing())

class PredictorTest(TestCase):
    """Test prediction functionality."""
    
    def test_validate_url(self):
        """Test URL validation."""
        self.assertTrue(validate_url('https://www.google.com'))
        self.assertTrue(validate_url('http://example.com'))
        self.assertFalse(validate_url('invalid-url'))
        self.assertFalse(validate_url(''))
    
    def test_make_prediction(self):
        """Test prediction function."""
        # Test with legitimate URL
        result = make_prediction('https://www.google.com')
        self.assertIn(result, ['Phishing', 'Legitimate'])
        
        # Test with invalid URL
        result = make_prediction('invalid-url')
        self.assertEqual(result, 'Error: Invalid URL format')

class APITest(APITestCase):
    """Test API endpoints."""
    
    def setUp(self):
        self.client = Client()
        self.scan_url = reverse('scan-url')
    
    def test_scan_url_success(self):
        """Test successful URL scanning."""
        data = {'url': 'https://www.google.com'}
        response = self.client.post(self.scan_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('result', response.data)
        self.assertIn('processing_time', response.data)
    
    def test_scan_url_invalid_data(self):
        """Test URL scanning with invalid data."""
        data = {'url': 'invalid-url'}
        response = self.client.post(self.scan_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('errors', response.data)
    
    def test_get_scan_logs(self):
        """Test getting scan logs."""
        # Create test data
        ScanResult.objects.create(
            url='https://www.google.com',
            result='Legitimate'
        )
        
        response = self.client.get(reverse('scan-logs'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_models_status(self):
        """Test models status endpoint."""
        response = self.client.get(reverse('models-status'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('models_status', response.data)
        self.assertIn('models_loaded', response.data)
```

### 2. Frontend Testing

```javascript
// CRITICAL: Frontend testing with Jest and React Testing Library
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ScanLogTable from '../components/ScanLogTable';

// Mock data
const mockScans = [
    {
        id: 1,
        url: 'https://www.google.com',
        result: 'Legitimate',
        timestamp: '2024-01-15T10:30:00Z'
    },
    {
        id: 2,
        url: 'https://suspicious-site.com',
        result: 'Phishing',
        timestamp: '2024-01-15T10:25:00Z'
    }
];

describe('ScanLogTable Component', () => {
    test('renders scan results correctly', () => {
        render(<ScanLogTable scans={mockScans} />);
        
        expect(screen.getByText('https://www.google.com')).toBeInTheDocument();
        expect(screen.getByText('https://suspicious-site.com')).toBeInTheDocument();
        expect(screen.getByText('✅ Legitimate')).toBeInTheDocument();
        expect(screen.getByText('⚠️ Phishing')).toBeInTheDocument();
    });
    
    test('handles sorting correctly', async () => {
        render(<ScanLogTable scans={mockScans} />);
        
        // Click on URL header to sort
        fireEvent.click(screen.getByText('🔗 URL'));
        
        // Check if sorting indicator appears
        expect(screen.getByText('🔗 URL ↓')).toBeInTheDocument();
    });
    
    test('handles filtering correctly', async () => {
        render(<ScanLogTable scans={mockScans} />);
        
        // Select phishing filter
        const filterSelect = screen.getByDisplayValue('All Results');
        fireEvent.change(filterSelect, { target: { value: 'Phishing' } });
        
        // Check if only phishing results are shown
        expect(screen.getByText('https://suspicious-site.com')).toBeInTheDocument();
        expect(screen.queryByText('https://www.google.com')).not.toBeInTheDocument();
    });
    
    test('displays empty state correctly', () => {
        render(<ScanLogTable scans={[]} />);
        
        expect(screen.getByText('No data to display')).toBeInTheDocument();
    });
    
    test('shows correct record count', () => {
        render(<ScanLogTable scans={mockScans} />);
        
        expect(screen.getByText('Showing 2 of 2 records')).toBeInTheDocument();
    });
});

// API integration testing
describe('API Integration', () => {
    test('handles API errors gracefully', async () => {
        // Mock fetch to return error
        global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));
        
        const { result } = renderHook(() => useScanData());
        
        await waitFor(() => {
            expect(result.current.error).toBeTruthy();
        });
    });
    
    test('handles successful API responses', async () => {
        // Mock fetch to return success
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ results: mockScans })
        });
        
        const { result } = renderHook(() => useScanData());
        
        await waitFor(() => {
            expect(result.current.scans).toEqual(mockScans);
            expect(result.current.loading).toBe(false);
        });
    });
});
```

---

## Deployment Code Examples

### 1. Docker Configuration

```dockerfile
# CRITICAL: Production-ready Dockerfile
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run the application
CMD ["gunicorn", "phish_guard_backend.wsgi:application", "--bind", "0.0.0.0:8000"]
```

### 2. Docker Compose Configuration

```yaml
# CRITICAL: Complete Docker Compose setup
version: '3.8'

services:
  db:
    image: postgres:13
    environment:
      POSTGRES_DB: phish_guard_backend
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 30s
      timeout: 10s
      retries: 3

  web:
    build: .
    command: >
      sh -c "python manage.py migrate &&
             python manage.py collectstatic --noinput &&
             gunicorn phish_guard_backend.wsgi:application --bind 0.0.0.0:8000"
    volumes:
      - .:/app
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
    environment:
      - DEBUG=False
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@db:5432/phish_guard_backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health/"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./static:/static
      - ./media:/media
    depends_on:
      - web

volumes:
  postgres_data:
```

### 3. Production Settings

```python
# CRITICAL: Production settings configuration
import os
from .base import *

# Security settings
DEBUG = False
SECRET_KEY = os.environ.get('SECRET_KEY')
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST'),
        'PORT': os.environ.get('DB_PORT'),
    }
}

# CORS settings for production
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',')

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/var/log/phish_guard/django.log',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['file'],
        'level': 'INFO',
    },
}

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

This comprehensive code examples guide provides practical implementations of all the critical patterns and functionality in the Phish-Guard system. Each example includes detailed explanations of why the code is important and how it contributes to the overall system functionality.
