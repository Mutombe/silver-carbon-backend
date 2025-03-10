# custom_middleware.py
from django.http import HttpResponse
from django.conf import settings
import os

class ServeMediaFileMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/media/'):
            # Strip '/media/' from the path
            relative_path = request.path[7:]
            file_path = os.path.join(settings.MEDIA_ROOT, relative_path)
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                    
                # Determine content type (you might want to expand this)
                content_type = 'image/jpeg'  # default
                if file_path.endswith('.png'):
                    content_type = 'image/png'
                elif file_path.endswith('.pdf'):
                    content_type = 'application/pdf'
                
                response = HttpResponse(file_content, content_type=content_type)
                return response

        return self.get_response(request)