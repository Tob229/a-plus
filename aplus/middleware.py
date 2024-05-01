# monapp/middleware.py

from django.http import HttpResponse
from django.conf import settings
import base64

class BasicAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Vérifier si la demande est pour /metrics
        if request.path == '/metrics':
            # Vérifier l'authentification de base
            auth_header = request.headers.get('Authorization')
            if not auth_header or not self._check_basic_auth(auth_header):
                # Demander l'authentification
                response = HttpResponse('Unauthorized', status=401)
                response['WWW-Authenticate'] = 'Basic realm="Prometheus Exporter"'
                return response

        return self.get_response(request)

    def _check_basic_auth(self, auth_header):
        try:
            method, b64_value = auth_header.split(' ')
            if method.lower() != 'basic':
                return False

            value = base64.b64decode(b64_value).decode('utf-8')
            username, password = value.split(':')
            return username == settings.BASIC_AUTH_USERNAME and password == settings.BASIC_AUTH_PASSWORD
        except:
            return False

