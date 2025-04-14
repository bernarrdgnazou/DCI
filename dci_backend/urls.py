from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

# Configuration de la documentation Swagger/OpenAPI
schema_view = get_schema_view(
    openapi.Info(
        title="API Plateforme DCI",
        default_version='v1',
        description="Documentation de l'API pour la plateforme de gestion des extraits de naissance",
        contact=openapi.Contact(email="support@dci-plateforme.com"),
        license=openapi.License(name="Licence DCI"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # Administration Django
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/', include([
        path('v1/', include('api.urls')),  # Versioning de l'API
        
        # Documentation interactive
        path('docs/', include([
            path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
            path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
        ])),
    ])),
    
    # Health check
    path('health/', include('health_check.urls')),
]

# Configuration pour les médias en développement
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug Toolbar
    import debug_toolbar
    urlpatterns += [path('__debug__/', include(debug_toolbar.urls))]

# Gestion des erreurs
handler400 = 'api.exceptions.bad_request'
handler403 = 'api.exceptions.permission_denied'
handler404 = 'api.exceptions.page_not_found'
handler500 = 'api.exceptions.server_error'