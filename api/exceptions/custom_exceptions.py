from rest_framework.exceptions import APIException
from django.utils.translation import gettext_lazy as _

class ResourceNotFoundError(APIException):
    status_code = 404
    default_detail = _("La ressource demandée n'existe pas.")
    default_code = 'resource_not_found'

class ValidationError(APIException):
    status_code = 400
    default_detail = _("Données invalides.")
    default_code = 'validation_error'

class AuthenticationFailedError(APIException):
    status_code = 401
    default_detail = _("Échec de l'authentification.")
    default_code = 'authentication_failed'

class PermissionDeniedError(APIException):
    status_code = 403
    default_detail = _("Vous n'avez pas les permissions nécessaires.")
    default_code = 'permission_denied'

class ServerError(APIException):
    status_code = 500
    default_detail = _("Une erreur interne s'est produite.")
    default_code = 'server_error'

class ServiceUnavailableError(APIException):
    status_code = 503
    default_detail = _("Le service est temporairement indisponible.")
    default_code = 'service_unavailable'

class BusinessLogicError(APIException):
    status_code = 422
    default_detail = _("L'opération ne peut pas être effectuée.")
    default_code = 'business_logic_error'


def bad_request(request, exception=None):
    return JsonResponse({
        'status_code': status.HTTP_400_BAD_REQUEST,
        'detail': 'Requête invalide',
        'code': 'bad_request'
    }, status=status.HTTP_400_BAD_REQUEST)

def permission_denied(request, exception=None):
    return JsonResponse({
        'status_code': status.HTTP_403_FORBIDDEN,
        'detail': 'Permission refusée',
        'code': 'permission_denied'
    }, status=status.HTTP_403_FORBIDDEN)

def page_not_found(request, exception=None):
    return JsonResponse({
        'status_code': status.HTTP_404_NOT_FOUND,
        'detail': 'Resource non trouvée',
        'code': 'not_found'
    }, status=status.HTTP_404_NOT_FOUND)

def server_error(request):
    return JsonResponse({
        'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
        'detail': 'Erreur serveur interne',
        'code': 'server_error'
    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)