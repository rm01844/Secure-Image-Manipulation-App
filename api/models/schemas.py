from marshmallow import Schema, fields, validate, validates, ValidationError
from datetime import datetime

# ============================================================================
# Authentication Schemas
# ============================================================================


class RegisterRequestSchema(Schema):
    first_name = fields.Str(
        required=True, validate=validate.Length(min=1, max=80))
    last_name = fields.Str(
        required=True, validate=validate.Length(min=1, max=80))
    email_id = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    confirm_password = fields.Str(required=True)

    @validates('password')
    def validate_password(self, value):
        if not any(c.isupper() for c in value):
            raise ValidationError('Password must contain uppercase letter')
        if not any(c.islower() for c in value):
            raise ValidationError('Password must contain lowercase letter')
        if not any(c.isdigit() for c in value):
            raise ValidationError('Password must contain number')
        if not any(c in '!@#$%^&*()_+-=' for c in value):
            raise ValidationError('Password must contain special character')


class LoginRequestSchema(Schema):
    email_id = fields.Email(required=True)
    password = fields.Str(required=True)


class LoginResponseSchema(Schema):
    message = fields.Str()
    token = fields.Str()
    api_key = fields.Str(allow_none=True)
    user = fields.Dict()
    expires_at = fields.DateTime()

# ============================================================================
# Image Processing Schemas
# ============================================================================


class ImageUploadRequestSchema(Schema):
    # File uploaded via multipart/form-data
    # Validated in route handler
    pass


class ImageProcessResponseSchema(Schema):
    success = fields.Bool()
    message = fields.Str()
    original_url = fields.Str()
    edited_url = fields.Str()
    processing_time = fields.Float()
    timestamp = fields.DateTime()

# ============================================================================
# API Key Schemas
# ============================================================================


class CreateAPIKeyRequestSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    expires_in_days = fields.Int(
        validate=validate.Range(min=1, max=365), missing=365)


class APIKeyResponseSchema(Schema):
    id = fields.Int()
    key = fields.Str()  # Only returned on creation
    key_prefix = fields.Str()
    name = fields.Str()
    is_active = fields.Bool()
    rate_limit = fields.Int()
    request_count = fields.Int()
    created_at = fields.DateTime()
    last_used = fields.DateTime(allow_none=True)
    expires_at = fields.DateTime(allow_none=True)

# ============================================================================
# User Schemas
# ============================================================================


class UserProfileSchema(Schema):
    id = fields.Int()
    first_name = fields.Str()
    last_name = fields.Str()
    email_id = fields.Email()
    role = fields.Str()
    is_verified = fields.Bool()
    profile_picture = fields.Str(allow_none=True)
    created_at = fields.DateTime()

# ============================================================================
# Error Schemas
# ============================================================================


class ErrorResponseSchema(Schema):
    error = fields.Str(required=True)
    message = fields.Str(required=True)
    details = fields.Dict(allow_none=True)
    timestamp = fields.DateTime(missing=datetime.utcnow)
