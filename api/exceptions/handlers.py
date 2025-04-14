import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from django.http import Http404
from rest_framework.exceptions import (
    AuthenticationFailed, NotAuthenticated, PermissionDenied, 
    ValidationError as DRFValidationError, NotFound
)
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError

logger = logging.getLogger('django')

def custom_exception_handler(exc, context):
    """
    Gestionnaire d'exceptions personnalisé pour les vues DRF
    """
    # Appel au gestionnaire d'exceptions par défaut de DRF
    response = exception_handler(exc, context)
    
    # Obtenir les informations sur la requête pour le logging
    request = context.get('request')
    view = context.get('view')
    view_name = view.__class__.__name__ if view else "Unknown"
    
    # Si DRF n'a pas géré l'exception, nous la gérons nous-mêmes
    if response is None:
        if isinstance(exc, Http404):
            logger.info(f"Resource not found in {view_name}: {str(exc)}")
            return Response(
                {'detail': 'La ressource demandée n\'existe pas.', 'code': 'not_found'},
                status=404
            )
        elif isinstance(exc, DjangoValidationError):
            logger.warning(f"Validation error in {view_name}: {str(exc)}")
            return Response(
                {'detail': str(exc), 'code': 'validation_error'},
                status=400
            )
        elif isinstance(exc, IntegrityError):
            logger.error(f"Database integrity error in {view_name}: {str(exc)}")
            return Response(
                {'detail': 'Cette opération viole une contrainte d\'intégrité.', 'code': 'integrity_error'},
                status=400
            )
        else:
            # Exceptions non gérées - les logger en tant qu'erreur
            logger.error(f"Unhandled exception in {view_name}: {str(exc)}", exc_info=True)
            return Response(
                {'detail': 'Une erreur interne s\'est produite.', 'code': 'server_error', 'debug_info': str(exc)},
                status=500
            )
    
    # Enrichir les réponses d'erreur avec des informations supplémentaires
    if response is not None:
        # Ajouter l'URL de la requête qui a causé l'erreur
        if request:
            response.data['request_url'] = request.path
        
        # Ajouter un code d'erreur pour faciliter le traitement côté client
        if isinstance(exc, AuthenticationFailed) or isinstance(exc, NotAuthenticated):
            response.data['code'] = 'authentication_failed'
            logger.warning(f"Authentication failed in {view_name}: {str(exc)}")
        elif isinstance(exc, PermissionDenied):
            response.data['code'] = 'permission_denied'
            logger.warning(f"Permission denied in {view_name}: {str(exc)}")
        elif isinstance(exc, DRFValidationError):
            response.data['code'] = 'validation_error'
            logger.warning(f"Validation error in {view_name}: {str(exc)}")
        elif isinstance(exc, NotFound):
            response.data['code'] = 'not_found'
            logger.info(f"Resource not found in {view_name}: {str(exc)}")
        else:
            response.data['code'] = 'error'
            logger.error(f"Other error in {view_name}: {str(exc)}")
            
        # Ajouter le status_code dans le corps de la réponse
        response.data['status_code'] = response.status_code
    
    return response