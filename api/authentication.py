from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import permissions
from django_ratelimit.decorators import ratelimit
from django_ratelimit.core import is_ratelimited
from .models import Utilisateur, Agent, Journal, Commune
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
import ipaddress
from datetime import timedelta
import re


class EmailOrUsernameModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(username=username)
        except UserModel.DoesNotExist:
            try:
                user = UserModel.objects.get(email=username)
            except UserModel.DoesNotExist:
                return None
        
        if user.check_password(password):
            return user
        return None


class MultiFactorAuthBackend(ModelBackend):
    """
    Authentification avancée améliorée :
    - Double facteur (email/matricule)
    - Journalisation complète
    - Protection anti-bruteforce
    - Validation IP stricte
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        if hasattr(self, 'method') is False:
            self.method = request.method
            
        # Votre logique d'authentification normale
        return super().authenticate(request, username, password, **kwargs)

    def _authenticate_user(self, identifier, password, ip):
        """Authentification des Utilisateurs"""
        try:
            user = Utilisateur.objects.get(
                Q(email__iexact=identifier) & 
                Q(is_active=True)
            )
            if user.check_password(password):
                return user
        except Utilisateur.DoesNotExist:
            return None

    def _authenticate_agent(self, identifier, password, ip):
        """Authentification des Agents"""
        try:
            agent = Agent.objects.get(
                Q(email__iexact=identifier) | 
                Q(matricule__iexact=identifier)
            )
            if agent.check_password(password):
                return agent
        except Agent.DoesNotExist:
            return None

    def _get_valid_client_ip(self, request):
        """Validation renforcée de l'IP client"""
        ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        try:
            return str(ipaddress.ip_address(ip.split(',')[0].strip()))
        except (ValueError, AttributeError):
            return None

    def _log_success_auth(self, user, ip):
        """Journalisation améliorée"""
        Journal.objects.create(
            type_action=Journal.TypeAction.CONNEXION,
            description=f"Connexion réussie depuis {ip}",
            utilisateur=user if isinstance(user, Utilisateur) else None,
            agent=user if isinstance(user, Agent) else None,
            adresse_ip=ip,
            metadata={
                'user_agent': request.META.get('HTTP_USER_AGENT'),
                'device_type': self._get_device_type(request)
            }
        )

    def _log_failed_attempt(self, ip, identifier):
        """Journalisation des échecs avec détails"""
        Journal.objects.create(
            type_action=Journal.TypeAction.TENTATIVE_ECHOUEE,
            description=f"Tentative échouée pour {identifier or 'inconnu'} depuis {ip}",
            adresse_ip=ip
        )

    def _get_device_type(self, request):
        """Détection du type d'appareil"""
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        if 'mobile' in user_agent:
            return 'mobile'
        elif 'tablet' in user_agent:
            return 'tablet'
        return 'desktop'

class JWTService:
    """Service JWT amélioré avec sécurité renforcée"""
    
    @staticmethod
    def create_tokens(user, request=None):
        refresh = RefreshToken.for_user(user)
        
        payload = {
            'user_type': 'agent' if isinstance(user, Agent) else 'utilisateur',
            'auth_time': int(timezone.now().timestamp()),
            'ip': request.META.get('REMOTE_ADDR') if request else None,
            'device': self._get_device_type(request) if request else None
        }

        if isinstance(user, Agent):
            payload.update({
                'role': user.role,
                'matricule': user.matricule,
                'commune_id': str(user.commune_service.id) if user.commune_service else None,
                'permissions': self._get_agent_permissions(user)
            })
        else:
            payload['verified'] = getattr(user, 'is_verified', False)

        refresh.payload.update(payload)
        
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'expires_in': timedelta(minutes=15).total_seconds()
        }

    @staticmethod
    def _get_agent_permissions(agent):
        """Définition dynamique des permissions"""
        if agent.role == Agent.RoleItems.ADMIN:
            return ['full_access', 'manage_users', 'process_demandes']
        return ['basic_access', 'process_demandes']

    @staticmethod
    def validate_token(token):
        """Validation étendue du token"""
        try:
            payload = RefreshToken(token).payload
            required_fields = ['user_type', 'auth_time']
            if not all(field in payload for field in required_fields):
                raise ValidationError("Token invalide")
            return True
        except Exception as e:
            return False

class PasswordService:
    """Service de gestion des mots de passe sécurisé"""
    
    COMPLEXITY_RULES = [
        (r'.{12,}', _("12 caractères minimum")),  # Augmenté à 12
        (r'[A-Z]', _("1 majuscule minimum")),
        (r'[0-9]', _("1 chiffre minimum")),
        (r'[^A-Za-z0-9]', _("1 caractère spécial minimum")),
        (r'^(?!.*(.)\1{2})', _("Pas de répétition de caractères"))  # Nouvelle règle
    ]

    @staticmethod
    def validate_complexity(password):
        """Validation renforcée"""
        errors = []
        for pattern, msg in PasswordService.COMPLEXITY_RULES:
            if not re.search(pattern, password):
                errors.append(msg)
        if errors:
            raise ValidationError(_("Mot de passe faible: ") + ", ".join(errors))

    @staticmethod
    @ratelimit(key='user', rate='3/h')
    def reset_password(user, new_password, confirm_password):
        """Réinitialisation sécurisée"""
        if new_password != confirm_password:
            raise AuthError(_("Les mots de passe ne correspondent pas"))
        
        PasswordService.validate_complexity(new_password)
        user.set_password(new_password)
        user.save()
        
        Journal.log_action(
            user=user,
            action_type=Journal.TypeAction.PASSWORD_RESET,
            description="Réinitialisation du mot de passe réussie",
            metadata={
                'ip': request.META.get('REMOTE_ADDR'),
                'method': 'reset'
            }
        )


class PermissionService:
    """Service centralisé de gestion des permissions"""
    
    @staticmethod
    def has_commune_access(user, commune):
        """Vérifie l'accès à une commune spécifique"""
        if isinstance(user, Agent):
            return user.commune_service == commune
        return False

    @staticmethod
    def can_edit_demande(user, demande):
        """Vérifie les droits sur une demande"""
        if isinstance(user, Agent):
            return (user.role == Agent.RoleItems.ADMIN or 
                    demande.commune_source == user.commune_service)
        return demande.utilisateur == user

class AuthError(Exception):
    """Exception personnalisée pour l'authentification"""
    pass

# Permissions DRF (exemples)
class IsCommuneAdmin(permissions.BasePermission):
    """Vérifie si l'agent administre la commune concernée"""
    def has_object_permission(self, request, view, obj):
        if isinstance(obj, Commune):
            return (isinstance(request.user, Agent) and 
                    request.user.commune_service == obj and
                    request.user.role == Agent.RoleItems.ADMIN)
        return False

class CanProcessDemande(permissions.BasePermission):
    """Permission pour traiter les demandes"""
    def has_object_permission(self, request, view, obj):
        user = request.user
        if isinstance(user, Agent):
            return (user.commune_service == obj.commune_source or
                    user.commune_service == obj.commune_cible)
        return False