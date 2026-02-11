from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
from api.middleware.auth import require_api_key, require_jwt_token
from api.models.schemas import ImageProcessResponseSchema, ErrorResponseSchema
from api.services.image_service import ImageProcessingService
from marshmallow import ValidationError

images_bp = Blueprint('images_api', __name__, url_prefix='/api/v1/images')


@images_bp.route('/process', methods=['POST'])
@require_api_key
def process_image():
    """
    Process an image and apply company t-shirt

    ---
    tags:
      - Images
    security:
      - ApiKeyAuth: []
    requestBody:
      required: true
      content:
        multipart/form-data:
          schema:
            type: object
            properties:
              image:
                type: string
                format: binary
                description: Image file to process
    responses:
      200:
        description: Image processed successfully
        content:
          application/json:
            schema: ImageProcessResponseSchema
      400:
        description: Invalid input
      401:
        description: Unauthorized
      500:
        description: Server error
    """
    try:
        # Check if image file is present
        if 'image' not in request.files:
            return jsonify({
                'error': 'No image provided',
                'message': 'Please upload an image file'
            }), 400

        file = request.files['image']

        if file.filename == '':
            return jsonify({
                'error': 'No file selected',
                'message': 'Please select a file to upload'
            }), 400

        # Get genai_client from app context
        from app import genai_client

        if not genai_client:
            return jsonify({
                'error': 'Service unavailable',
                'message': 'Image processing service is not configured'
            }), 503

        # Process image
        result = ImageProcessingService.process_image(
            file=file,
            user_id=request.api_user_id,
            genai_client=genai_client
        )

        # Serialize response
        schema = ImageProcessResponseSchema()
        return jsonify(schema.dump(result)), 200

    except ValueError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        print(f"Image processing error: {e}")
        return jsonify({
            'error': 'Processing failed',
            'message': 'An error occurred while processing your image'
        }), 500


@images_bp.route('/history', methods=['GET'])
@require_api_key
def get_image_history():
    """
    Get user's image processing history

    ---
    tags:
      - Images
    security:
      - ApiKeyAuth: []
    parameters:
      - name: limit
        in: query
        schema:
          type: integer
          default: 10
        description: Number of results to return
    responses:
      200:
        description: Image history retrieved
      401:
        description: Unauthorized
    """
    from app import get_db_connection

    limit = request.args.get('limit', 10, type=int)

    # This would require an image_history table - simplified example
    return jsonify({
        'images': [],
        'total': 0,
        'message': 'Feature coming soon'
    }), 200
