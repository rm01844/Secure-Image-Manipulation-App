# Secure-Image-Manipulation-Web-App

## Overview
A secure Flask web application that uses Google Gemini AI to automatically apply a company uniform t-shirt onto user-uploaded photos while preserving all other facial features and background elements.

## Features
- ✅ Secure user authentication with email verification
- ✅ Role-based access control (User/Admin/Superadmin)
- ✅ Webcam capture and file upload support
- ✅ AI-powered t-shirt replacement using Google Gemini 2.5
- ✅ Face detection validation
- ✅ Profile picture management
- ✅ Admin dashboard for user management
- ✅ CSRF protection and reCAPTCHA

## Prerequisites
- Python 3.13+
- Gmail account (for SMTP)
- Google Cloud account with Vertex AI enabled
- reCAPTCHA v2 site key and secret key

## Installation

### 1. Clone the Repository
```bash
git clone <https://github.com/rm01844/Secure-Image-Manipulation-App>
cd img_mani_web_app
```

### 2. Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirement.txt
```

### 4. Set Up Google Cloud Credentials

1. Create a Google Cloud project
2. Enable Vertex AI API
3. Create a service account and download JSON key
4. Place the JSON file in the project root

### 5. Configure Environment Variables

Create a `.env` file in the project root:
```env
# Flask Configuration
FLASK_SECRET=your_super_secret_key_min_32_chars
JWT_SECRET_KEY=another_secret_key_for_jwt

# Mail Configuration
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_gmail_app_password

# Admin Configuration
ADMIN_KEY=admin_registration_key
SUPERADMIN_EMAIL=admin@example.com
SUPERADMIN_PASSWORD=SecurePassword123!

# Google Cloud Configuration
PROJECT_ID=your-google-cloud-project-id
LOCATION=us-central1
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# reCAPTCHA (get from https://www.google.com/recaptcha)
RECAPTCHA_SITE_KEY=your_site_key
RECAPTCHA_SECRET_KEY=your_secret_key
```

### 6. Gmail App Password Setup

1. Go to Google Account → Security
2. Enable 2-Step Verification
3. Go to App Passwords
4. Generate password for "Mail"
5. Use this password in `MAIL_PASSWORD`

### 7. Initialize Database
```bash
python3 app.py
# Database will be created automatically on first run
# Superadmin account created from .env variables
```

## Running the Application
```bash
python3 app.py
```

Visit: `http://127.0.0.1:5000`

## Usage

### For Users:
1. Register account → Verify email → Login
2. Upload image or use webcam
3. AI processes and applies company t-shirt
4. Download or set as profile picture

### For Admins:
1. Login → Click "Admin Dashboard"
2. View all users and profile pictures
3. Promote/demote users
4. Delete user profile pictures
5. Switch back to user view

## API Endpoints

### Authentication
- `POST /register/` - User registration
- `POST /login/` - User login
- `GET /verify_email/<token>` - Email verification
- `POST /forgot_password/` - Request password reset
- `POST /reset_password/<token>` - Reset password

### Image Processing
- `POST /api/edit-image` - Upload and edit image (requires authentication)

### API Authentication
- `POST /api/register` - API registration
- `POST /api/login` - API login (returns JWT token)
- `GET /api/verify_email/<token>` - API email verification

### Admin Routes

To create the first admin, navigate to the register.html and scroll below to find Account type and uncomment it before running. Opt for Admin account and once the DB is connected successfully and the Admin credentials are stored then comment it out.
- `GET /admin/dashboard` - Admin user management
- `POST /admin/promote/<user_id>` - Promote user to admin
- `POST /admin/demote/<user_id>` - Demote admin to user
- `POST /admin/delete-picture/<user_id>` - Delete user profile picture

## Security Features

- **Password Requirement:** Min 8 chars, uppercase, lowercase, number, special character
- **CSRF Protection:** All forms protected
- **Login Attempts:** Max 5 attempts, 10-minute lockout
- **Email Verification:** Required before account activation
- **reCAPTCHA:** Bot protection on registration/login
- **Session Management:** 1-hour timeout
- **Role-Based Access:** User/Admin/Superadmin levels
- **Face Detection:** Only human faces allowed

## Tech Stack

**Backend:** Flask, SQLAlchemy, SQLite  
**AI/ML:** Google Gemini 2.5 Flash Image, OpenCV, InsightFace  
**Authentication:** Flask-Login, PyJWT, Flask-WTF  
**Email:** Flask-Mail, Gmail SMTP  
**Frontend:** HTML5, CSS3, JavaScript (Vanilla)

## Troubleshooting

### Database Errors
```bash
# Reset database
rm users.db
python3 app.py
```

### API Rate Limit (429 Error)
- Wait a few minutes between requests
- Check Google Cloud quota
- Consider upgrading to paid tier

### Email Not Sending
- Verify Gmail app password
- Check SMTP settings
- Ensure 2FA enabled on Gmail

### Face Detection Fails
- Ensure good lighting
- Face too far away
- Face clearly visible
- Try different photo angle

# Image Manipulation API Documentation

## Base URL
```
https://your-domain.com/api/v1
```

## Authentication

### Method 1: API Key (Recommended)
Include your API key in the `X-API-Key` header:
```bash
X-API-Key: sk_1234567890abcdef1234567890abcdef1234567890
```

### Method 2: JWT Token
Include Bearer token in `Authorization` header:
```bash
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Getting Started

### Step 1: Register
```bash
curl -X POST https://your-domain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Cena",
    "email_id": "john_cena@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!"
  }'
```

### Step 2: Login
```bash
curl -X POST https://your-domain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email_id": "john_cena@example.com",
    "password": "SecurePass123!"
  }'
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "john@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user"
  },
  "expires_at": "2026-01-25T12:00:00Z"
}
```

### Step 3: Create API Key (Optional but Recommended)
```bash
curl -X POST https://your-domain.com/api/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Production Key",
    "expires_in_days": 365
  }'
```

**Response:**
```json
{
  "id": 1,
  "key": "sk_1234567890abcdef1234567890abcdef1234567890",
  "key_prefix": "sk_123456789...",
  "name": "My Production Key",
  "is_active": true,
  "rate_limit": 100,
  "request_count": 0,
  "created_at": "2026-01-24T10:00:00Z",
  "expires_at": "2027-01-24T10:00:00Z"
}
```

⚠️ **Important:** Save the full API key securely. It will only be shown once!

### Step 4: Process an Image
```bash
curl -X POST https://your-domain.com/api/v1/images/process \
  -H "X-API-Key: sk_1234567890abcdef1234567890abcdef1234567890" \
  -F "image=@/path/to/your/photo.jpg"
```

**Response:**
```json
{
  "success": true,
  "message": "Image processed successfully",
  "original_url": "/static/uploads/upload_1_abc123.png",
  "edited_url": "/static/edited/edited_1_def456.png",
  "processing_time": 12.34,
  "timestamp": "2026-01-24T10:30:00Z"
}
```

## Endpoints

### Authentication

#### POST /api/v1/auth/register
Register a new user account.

**Request Body:**
```json
{
  "first_name": "string",
  "last_name": "string",
  "email_id": "string",
  "password": "string",
  "confirm_password": "string"
}
```

**Response: 201 Created**
```json
{
  "message": "User registered successfully",
  "user_id": 1,
  "verification_token": "...",
  "note": "Please verify your email before logging in"
}
```

#### POST /api/v1/auth/login
Login and receive JWT token.

**Request Body:**
```json
{
  "email_id": "string",
  "password": "string"
}
```

**Response: 200 OK**
```json
{
  "message": "Login successful",
  "token": "string",
  "user": {...},
  "expires_at": "datetime"
}
```

#### POST /api/v1/auth/api-keys
Create a new API key (requires JWT token).

**Headers:**
```
Authorization: Bearer YOUR_JWT_TOKEN
```

**Request Body:**
```json
{
  "name": "string",
  "expires_in_days": 365
}
```

**Response: 201 Created**
```json
{
  "id": 1,
  "key": "sk_...",
  "name": "string",
  "is_active": true,
  "rate_limit": 100,
  "created_at": "datetime",
  "expires_at": "datetime"
}
```

#### GET /api/v1/auth/api-keys
List all API keys for the authenticated user.

**Headers:**
```
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response: 200 OK**
```json
{
  "api_keys": [...],
  "total": 5
}
```

### Image Processing

#### POST /api/v1/images/process
Process an image and apply company t-shirt.

**Headers:**
```
X-API-Key: YOUR_API_KEY
```

**Request Body (multipart/form-data):**
```
image: file (required)
```

**Response: 200 OK**
```json
{
  "success": true,
  "message": "Image processed successfully",
  "original_url": "/static/uploads/upload_1_abc123.png",
  "edited_url": "/static/edited/edited_1_def456.png",
  "processing_time": 12.34,
  "timestamp": "2026-01-24T10:30:00Z"
}
```

**Error Responses:**

**400 Bad Request:**
```json
{
  "error": "Validation error",
  "message": "No human face detected. Please upload a photo with a person."
}
```

**401 Unauthorized:**
```json
{
  "error": "API key missing",
  "message": "Please provide X-API-Key header"
}
```

**429 Too Many Requests:**
```json
{
  "error": "Rate limit exceeded",
  "message": "You have exceeded your rate limit. Please try again later."
}
```

**500 Internal Server Error:**
```json
{
  "error": "Processing failed",
  "message": "An error occurred while processing your image"
}
```

## Rate Limits

- **Default:** 100 requests per hour per API key
- Rate limits reset every hour
- Upgrade plans available for higher limits

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing or invalid credentials |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Something went wrong |
| 503 | Service Unavailable - AI service is down |

## Best Practices

1. **Store API keys securely** - Never commit them to version control
2. **Use HTTPS** - Always use HTTPS in production
3. **Handle errors gracefully** - Implement retry logic for temporary failures
4. **Respect rate limits** - Monitor your usage and implement caching
5. **Validate responses** - Always check the `success` field before proceeding

# API Key Usage Examples

## Python

### Basic Example
```python
import requests

API_KEY = "sk_1234567890abcdef1234567890abcdef1234567890"
BASE_URL = "https://your-domain.com/api/v1"

# Process an image
with open("photo.jpg", "rb") as image_file:
    response = requests.post(
        f"{BASE_URL}/images/process",
        headers={"X-API-Key": API_KEY},
        files={"image": image_file}
    )

if response.status_code == 200:
    result = response.json()
    print(f"Success! Edited image: {result['edited_url']}")
    print(f"Processing time: {result['processing_time']}s")
else:
    print(f"Error: {response.json()['message']}")
```

### Advanced Example with Error Handling
```python
import requests
import time
from typing import Optional, Dict

class ImageManipulationAPI:
    def __init__(self, api_key: str, base_url: str = "https://your-domain.com/api/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key})
    
    def process_image(self, image_path: str, max_retries: int = 3) -> Optional[Dict]:
        """
        Process an image with retry logic
        
        Args:
            image_path: Path to the image file
            max_retries: Maximum number of retry attempts
            
        Returns:
            Dict with processed image data or None if failed
        """
        for attempt in range(max_retries):
            try:
                with open(image_path, "rb") as image_file:
                    response = self.session.post(
                        f"{self.base_url}/images/process",
                        files={"image": image_file},
                        timeout=60
                    )
                
                if response.status_code == 200:
                    return response.json()
                
                elif response.status_code == 429:
                    # Rate limited - wait and retry
                    wait_time = 2 ** attempt
                    print(f"Rate limited. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                elif response.status_code == 401:
                    raise Exception("Invalid API key")
                
                else:
                    error = response.json()
                    raise Exception(f"API Error: {error.get('message')}")
                    
            except requests.exceptions.RequestException as e:
                print(f"Request failed (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
        
        return None
    
    def download_image(self, url: str, save_path: str):
        """Download processed image"""
        response = self.session.get(self.base_url.replace("/api/v1", "") + url)
        with open(save_path, "wb") as f:
            f.write(response.content)

# Usage
api = ImageManipulationAPI(api_key="sk_your_api_key")

result = api.process_image("input.jpg")
if result:
    api.download_image(result['edited_url'], "output.png")
    print(f"Image processed in {result['processing_time']}s")
```

---

## JavaScript (Node.js)

### Basic Example
```javascript
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

const API_KEY = 'sk_1234567890abcdef1234567890abcdef1234567890';
const BASE_URL = 'https://your-domain.com/api/v1';

async function processImage(imagePath) {
    const form = new FormData();
    form.append('image', fs.createReadStream(imagePath));
    
    try {
        const response = await axios.post(
            `${BASE_URL}/images/process`,
            form,
            {
                headers: {
                    'X-API-Key': API_KEY,
                    ...form.getHeaders()
                }
            }
        );
        
        console.log('Success!', response.data);
        return response.data;
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
        throw error;
    }
}

// Usage
processImage('photo.jpg')
    .then(result => {
        console.log(`Edited image: ${result.edited_url}`);
        console.log(`Processing time: ${result.processing_time}s`);
    })
    .catch(console.error);
```

### React Example
```jsx
import React, { useState } from 'react';
import axios from 'axios';

const ImageProcessor = () => {
    const [file, setFile] = useState(null);
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    
    const API_KEY = process.env.REACT_APP_API_KEY;
    const BASE_URL = 'https://your-domain.com/api/v1';
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!file) return;
        
        setLoading(true);
        setError(null);
        
        const formData = new FormData();
        formData.append('image', file);
        
        try {
            const response = await axios.post(
                `${BASE_URL}/images/process`,
                formData,
                {
                    headers: {
                        'X-API-Key': API_KEY
                    }
                }
            );
            
            setResult(response.data);
        } catch (err) {
            setError(err.response?.data?.message || 'Processing failed');
        } finally {
            setLoading(false);
        }
    };
    
    return (
        <div>
            <form onSubmit={handleSubmit}>
                <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => setFile(e.target.files[0])}
                />
                <button type="submit" disabled={loading || !file}>
                    {loading ? 'Processing...' : 'Process Image'}
                </button>
            </form>
            
            {error && <div className="error">{error}</div>}
            
            {result && (
                <div>
                    <h3>Result:</h3>
                    <img src={BASE_URL.replace('/api/v1', '') + result.edited_url} alt="Edited" />
                    <p>Processing time: {result.processing_time}s</p>
                </div>
            )}
        </div>
    );
};

export default ImageProcessor;
```

---

## cURL Examples

### Register
```bash
curl -X POST https://your-domain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Cena",
    "email_id": "john_cena@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!"
  }'
```

### Login
```bash
curl -X POST https://your-domain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email_id": "john_cena@example.com",
    "password": "SecurePass123!"
  }'
```

### Create API Key
```bash
curl -X POST https://your-domain.com/api/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Key",
    "expires_in_days": 365
  }'
```

### Process Image
```bash
curl -X POST https://your-domain.com/api/v1/images/process \
  -H "X-API-Key: sk_your_api_key" \
  -F "image=@photo.jpg"
```

---

## PHP Example
```php
<?php

class ImageManipulationAPI {
    private $apiKey;
    private $baseUrl;
    
    public function __construct($apiKey, $baseUrl = 'https://your-domain.com/api/v1') {
        $this->apiKey = $apiKey;
        $this->baseUrl = $baseUrl;
    }
    
    public function processImage($imagePath) {
        $ch = curl_init();
        
        $file = new CURLFile($imagePath);
        $data = ['image' => $file];
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->baseUrl . '/images/process',
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'X-API-Key: ' . $this->apiKey
            ]
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200) {
            return json_decode($response, true);
        } else {
            throw new Exception("API Error: " . $response);
        }
    }
}

// Usage
$api = new ImageManipulationAPI('sk_your_api_key');

try {
    $result = $api->processImage('photo.jpg');
    echo "Success! Edited image: " . $result['edited_url'] . "\n";
    echo "Processing time: " . $result['processing_time'] . "s\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
```

---

## Ruby Example
```ruby
require 'httparty'

class ImageManipulationAPI
  def initialize(api_key, base_url = 'https://your-domain.com/api/v1')
    @api_key = api_key
    @base_url = base_url
  end
  
  def process_image(image_path)
    response = HTTParty.post(
      "#{@base_url}/images/process",
      headers: { 'X-API-Key' => @api_key },
      body: { image: File.new(image_path) }
    )
    
    if response.code == 200
      response.parsed_response
    else
      raise "API Error: #{response['message']}"
    end
  end
end

# Usage
api = ImageManipulationAPI.new('sk_your_api_key')

begin
  result = api.process_image('photo.jpg')
  puts "Success! Edited image: #{result['edited_url']}"
  puts "Processing time: #{result['processing_time']}s"
rescue => e
  puts "Error: #{e.message}"
end
```

## Project Structure
```
.env                   - Environment variables (not in repo)
api/                   - (middleware, models, routes and services)
app.py                 - Main application (routes, auth, API)
requirement.txt        - Python dependencies
run_api.py             - API Key
static/uploads/        - User uploaded images
static/edited/         - AI-edited images
templates/             - HTML templates
users.db               - SQLite database


```

## Support
For issues, please create a GitHub issue or contact: [raqeebmhd619@gmail.com]

## Acknowledgments
- Google Gemini AI for image processing
- OpenCV for face detection
- Flask framework and community
