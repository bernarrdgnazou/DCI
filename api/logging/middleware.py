import time
import logging
import uuid
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('django.request')

class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware pour logger les informations de chaque requête
    """
    def process_request(self, request):
        # Générer un ID unique pour chaque requête
        request.request_id = str(uuid.uuid4())
        # Stocker le temps de début pour calculer la durée
        request.start_time = time.time()
        
        # Éviter de logger les informations sensibles comme les mots de passe
        safe_data = {}
        if request.method in ['POST', 'PUT', 'PATCH']:
            for key, value in request.POST.items():
                if 'password' not in key.lower() and 'token' not in key.lower():
                    safe_data[key] = value
        
        logger.info(
            f"Request started: {request.method} {request.path}",
            extra={
                'request_id': request.request_id,
                'method': request.method,
                'path': request.path,
                'user_id': getattr(request.user, 'id', None),
                'user': str(getattr(request.user, 'username', 'Anonymous')),
                'ip': self.get_client_ip(request),
                'data': safe_data
            }
        )
        return None

    def process_response(self, request, response):
        # Calculer la durée de la requête si le temps de début est disponible
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
            
            # Logger les informations de la réponse
            logger.info(
                f"Request finished: {request.method} {request.path} - {response.status_code}",
                extra={
                    'request_id': getattr(request, 'request_id', 'unknown'),
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'duration': round(duration * 1000, 2),  # en millisecondes
                    'user_id': getattr(request.user, 'id', None),
                    'user': str(getattr(request.user, 'username', 'Anonymous')),
                    'ip': self.get_client_ip(request)
                }
            )
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip