from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView
)
from .views import (
    # ViewSets
    UtilisateurViewSet, CommuneViewSet, AgentViewSet,
    DemandeViewSet, EnregistrementViewSet, PaiementViewSet,
    RejetViewSet, JournalViewSet, NotificationViewSet,
    
    # Authentication
    TokenObtainPairView, LogoutView,
    PasswordChangeView, PasswordResetView, PasswordResetConfirmView,
    
    # Additional views
    DashboardStatsView, ExportDataView
)
from api.exceptions import bad_request, permission_denied, page_not_found, server_error
from django.contrib.auth.views import LoginView



router = DefaultRouter(trailing_slash=False)

# Core endpoints
router.register(r'utilisateurs', UtilisateurViewSet, basename='utilisateur')
router.register(r'communes', CommuneViewSet, basename='commune')
router.register(r'agents', AgentViewSet, basename='agent')
router.register(r'demandes', DemandeViewSet, basename='demande')
router.register(r'enregistrements', EnregistrementViewSet, basename='enregistrement')
router.register(r'paiements', PaiementViewSet, basename='paiement')
router.register(r'rejets', RejetViewSet, basename='rejet')
router.register(r'journal', JournalViewSet, basename='journal')
router.register(r'notifications', NotificationViewSet, basename='notification')

# Authentication URLs
auth_patterns = [
    # Authentification JWT
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('logout/', LogoutView.as_view(), name='auth-logout'),
    path('password/change/', PasswordChangeView.as_view(), name='auth-password-change'),
    path('password/reset/', PasswordResetView.as_view(), name='auth-password-reset'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='auth-password-reset-confirm'),

    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('schema/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# Custom actions
demande_actions = [
    path('<uuid:pk>/prendre-en-charge/', DemandeViewSet.as_view({'post': 'prendre_en_charge'})),
    path('<uuid:pk>/traiter/', DemandeViewSet.as_view({'post': 'traiter'})),
    path('<uuid:pk>/rejeter/', DemandeViewSet.as_view({'post': 'rejeter'})),
    path('statistiques/', DemandeViewSet.as_view({'get': 'statistiques'})),
]

paiement_actions = [
    path('<uuid:pk>/verifier/',
         PaiementViewSet.as_view({'post': 'verify'})),
    path('statistiques/',
         PaiementViewSet.as_view({'get': 'statistiques'})),
]


notification_actions = [
    path('<int:pk>/marquer-lue/', 
         NotificationViewSet.as_view({'post': 'marquer_lue'}), 
         name='notification-marquer-lue'),
]

# Additional services
service_patterns = [
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('export/<str:model_type>/', ExportDataView.as_view(), name='export-data'),
]

urlpatterns = [
    # API Root
    path('', include(router.urls)),
    # Authentication
    path('auth/', include(auth_patterns)),
    
    # Resources custom actions
    path('demandes/', include(demande_actions)),
    path('paiements/', include(paiement_actions)),
    path('notifications/', include(notification_actions)),

    
    # Services
    path('services/', include(service_patterns)),
    
    # Documentation
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
]