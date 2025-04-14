from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from django.core.paginator import InvalidPage
from rest_framework.exceptions import NotFound
from django.utils.translation import gettext_lazy as _
from rest_framework import pagination, permissions




class IsAdminWithFullRights(permissions.BasePermission):
    """Donne tous les droits à l'administrateur"""
    def has_permission(self, request, view):
        return request.user.role == Utilisateur.RoleChoices.ADMIN
        
    def has_object_permission(self, request, view, obj):
        return request.user.role == Utilisateur.RoleChoices.ADMIN


class CustomPagination(PageNumberPagination):
    """Pagination personnalisée avec des fonctionnalités étendues"""
    
    # Paramètres de base
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    page_query_param = 'page'
    
    # Métadonnées supplémentaires
    total_pages = None
    next_page = None
    previous_page = None
    
    def paginate_queryset(self, queryset, request, view=None):
        """
        Surcharge pour ajouter des vérifications de permissions
        """
        # Vérification des permissions si nécessaire
        if hasattr(view, 'check_pagination_permissions'):
            view.check_pagination_permissions(request)
            
        try:
            return super().paginate_queryset(queryset, request, view)
        except InvalidPage as exc:
            raise NotFound(_('Page invalide: {message}').format(message=str(exc)))

    def get_paginated_response(self, data):
        """
        Format de réponse personnalisé avec métadonnées étendues
        """
        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'first': self.get_first_link(),
                'last': self.get_last_link(),
            },
            'count': self.page.paginator.count,
            'page_size': self.get_page_size(self.request),
            'total_pages': self.page.paginator.num_pages,
            'current_page': self.page.number,
            'results': data,
            'filters': self.get_filters_info(),
        })
    
    def get_first_link(self):
        """Génère le lien vers la première page"""
        if not self.page.has_previous():
            return None
        url = self.request.build_absolute_uri()
        return self.replace_query_param(url, self.page_query_param, 1)
    
    def get_last_link(self):
        """Génère le lien vers la dernière page"""
        if not self.page.has_next():
            return None
        url = self.request.build_absolute_uri()
        return self.replace_query_param(
            url, 
            self.page_query_param, 
            self.page.paginator.num_pages
        )
    
    def get_filters_info(self):
        """Extrait les paramètres de filtrage de la requête"""
        filters = {}
        for param in self.request.query_params:
            if param not in [self.page_query_param, self.page_size_query_param]:
                filters[param] = self.request.query_params.get(param)
        return filters

class PermissionAwarePagination(CustomPagination):
    """Pagination consciente des permissions"""
    
    def get_page_size(self, request):
        """
        Détermine la taille de page en fonction des permissions
        """
        default_size = super().get_page_size(request)
        
        if request.user.role == Utilisateur.RoleChoices.ADMIN:
            return min(default_size, 500)
        elif request.user.role == Utilisateur.RoleChoices.SUPERVISOR:
            return min(default_size, 200)
        elif request.user.role == Utilisateur.RoleChoices.AGENT:
            return min(default_size, 100)
        else:  # Standard user
            return min(default_size, 50)



class CommunePagination(CustomPagination):
    """Pagination spéciale pour les communes avec plus d'éléments par défaut"""
    page_size = 50
    max_page_size = 200


class LargeResultsPagination(CustomPagination):
    """Pagination pour les grands ensembles de résultats"""
    page_size = 100
    max_page_size = 500


class SmallResultsPagination(CustomPagination):
    """Pagination pour les petits ensembles de résultats"""
    page_size = 10
    max_page_size = 50


class DemandePagination(CustomPagination):
    """Pagination spéciale pour les demandes avec tri par défaut"""
    page_size = 25
    ordering = '-date_demande'
    
    def paginate_queryset(self, queryset, request, view=None):
        # Applique le tri par défaut si aucun tri n'est spécifié
        if 'ordering' not in request.query_params:
            queryset = queryset.order_by(self.ordering)
        return super().paginate_queryset(queryset, request, view)


class RestrictedPagination(CustomPagination):
    """Pagination avec restrictions basées sur les permissions"""
    
    def paginate_queryset(self, queryset, request, view=None):
        """
        Applique des restrictions supplémentaires basées sur les permissions
        """
        # Exemple: restriction pour les utilisateurs non-admin
        if not request.user.is_superuser:
            self.page_size = min(self.page_size, 50)
            self.max_page_size = 50
            
        return super().paginate_queryset(queryset, request, view)