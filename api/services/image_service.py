import os
import uuid
import time
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
import cv2
from flask import current_app
from google.genai.types import GenerateContentConfig


class ImageProcessingService:

    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

    @staticmethod
    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower(
               ) in ImageProcessingService.ALLOWED_EXTENSIONS

    @staticmethod
    def detect_face(image_path):
        """Detect human face in image using OpenCV"""
        try:
            face_cascade = cv2.CascadeClassifier(
                cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            )

            img = cv2.imread(image_path)
            if img is None:
                return False

            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
            )

            return len(faces) > 0

        except Exception as e:
            print(f"Face detection error: {e}")
            return False

    @staticmethod
    def process_image(file, user_id, genai_client):
        """
        Process uploaded image and apply company t-shirt

        Args:
            file: FileStorage object from Flask request
            user_id: ID of the user uploading
            genai_client: Google Gemini client instance

        Returns:
            dict: Processing result with URLs and metadata
        """
        start_time = time.time()

        # Validate file
        if not file:
            raise ValueError("No file provided")

        if not ImageProcessingService.allowed_file(file.filename):
            raise ValueError("Invalid file type. Allowed: png, jpg, jpeg, gif")

        # Save uploaded file
        filename = secure_filename(file.filename)
        upload_filename = f"upload_{user_id}_{uuid.uuid4().hex}.png"
        upload_path = os.path.join(
            current_app.config['UPLOAD_FOLDER'],
            upload_filename
        )

        file.save(upload_path)

        # Check file size
        file_size = os.path.getsize(upload_path)
        if file_size > ImageProcessingService.MAX_FILE_SIZE:
            os.remove(upload_path)
            raise ValueError(f"File too large. Max size: 16MB")

        # Detect face
        if not ImageProcessingService.detect_face(upload_path):
            os.remove(upload_path)
            raise ValueError(
                "No human face detected. Please upload a photo with a person.")

        # Read image bytes
        with open(upload_path, "rb") as f:
            image_bytes = f.read()

        # AI Processing
        prompt = """Replace ONLY the shirt/t-shirt/top that the person is wearing with the company uniform t-shirt.

CRITICAL REQUIREMENTS:
1. Preserve EVERYTHING about the person: face, skin tone, hair, facial features, body shape, pose
2. Keep the EXACT same background, lighting, and image quality
3. ONLY change the shirt/t-shirt to match the company uniform design
4. The new t-shirt must fit naturally on the person's body with correct perspective and wrinkles
5. Maintain the same pose and arm positions
6. Keep all accessories (watches, glasses, etc.) unchanged

The company t-shirt design: Black t-shirt with white circular logo that says "SUPPORT SMALL BUSINESS" in a badge/stamp style.

Apply this t-shirt design naturally to the person while preserving everything else in the image."""

        # Retry logic for API rate limits
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                response = genai_client.models.generate_content(
                    model="gemini-2.5-flash-image",
                    contents=[
                        {"role": "user", "parts": [
                            {"text": prompt},
                            {"inline_data": {
                                "mime_type": "image/png", "data": image_bytes}}
                        ]}
                    ],
                    config=GenerateContentConfig(
                        response_modalities=["IMAGE"],
                        candidate_count=1,
                    ),
                )
                break

            except Exception as api_error:
                if "429" in str(api_error) or "RESOURCE_EXHAUSTED" in str(api_error):
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    else:
                        raise ValueError(
                            "API quota exceeded. Please try again later.")
                else:
                    raise

        # Save edited image
        edited_filename = f"edited_{user_id}_{uuid.uuid4().hex}.png"
        edited_path = os.path.join(
            current_app.config['EDITED_FOLDER'],
            edited_filename
        )

        for part in response.candidates[0].content.parts:
            if hasattr(part, "inline_data"):
                with open(edited_path, "wb") as f:
                    f.write(part.inline_data.data)

        processing_time = time.time() - start_time

        return {
            'success': True,
            'original_url': f"/static/uploads/{upload_filename}",
            'edited_url': f"/static/edited/{edited_filename}",
            'processing_time': round(processing_time, 2),
            'timestamp': datetime.now(timezone.utc)
        }
