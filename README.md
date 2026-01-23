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

## Project Structure
```
app.py                  - Main application (routes, auth, API)
templates/              - HTML templates
static/uploads/         - User uploaded images
static/edited/          - AI-edited images
users.db               - SQLite database
.env                   - Environment variables (not in repo)
requirement.txt       - Python dependencies
```

## Support
For issues, please create a GitHub issue or contact: [raqeebmhd619@gmail.com]

## Acknowledgments
- Google Gemini AI for image processing
- OpenCV for face detection
- Flask framework and community
