from django.contrib.auth import authenticate, login, logout
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.db.models import Q
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import path, include


from rest_framework import status, permissions, viewsets, generics, filters, routers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


from .models import (
    Utilisateur, Commune, Agent, Demande, Enregistrement,
    Paiement, Rejet, Journal, Notification
)
from .serializers import (
    UtilisateurSerializer, UtilisateurListSerializer, UtilisateurUpdateSerializer,
    CommuneSerializer, CommuneListSerializer,
    AgentSerializer, AgentListSerializer, AgentUpdateSerializer,
    DemandeSerializer, DemandeCreateSerializer, DemandeUpdateSerializer, DemandeListSerializer,
    EnregistrementSerializer, EnregistrementListSerializer,
    PaiementSerializer, PaiementCreateSerializer, PaiementUpdateSerializer,
    RejetSerializer, RejetCreateSerializer,
    JournalSerializer, JournalCreateSerializer,
    NotificationSerializer, NotificationCreateSerializer, NotificationUpdateSerializer,
    LoginSerializer, AgentLoginSerializer,
    PasswordChangeSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer
)

from .permissions import *
from rest_framework.renderers import JSONRenderer, BrowsableAPIRenderer
from django.contrib.auth.views import LoginView
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from .pagination import *


class DashboardStatsView(APIView):
    """
    Vue pour les statistiques du tableau de bord
    Permissions : Admin ou Agent
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Vérifier les permissions
        if not isinstance(request.user, (Agent, Utilisateur)):
            return Response({"error": "Accès non autorisé"}, status=403)

        # Période par défaut : 30 derniers jours
        end_date = timezone.now()
        start_date = end_date - timedelta(days=30)

        # Statistiques des demandes
        demandes_stats = Demande.objects.filter(
            date_demande__range=(start_date, end_date)
        ).aggregate(
            total=Count('id'),
            en_attente=Count('id', filter=Q(statut='en_attente')),
            en_cours=Count('id', filter=Q(statut='en_cours')),
            traitees=Count('id', filter=Q(statut='traitee')),
            rejetees=Count('id', filter=Q(statut='rejetee'))
        )

        # Statistiques utilisateurs/agents (seulement pour les admins)
        users_stats = {}
        if isinstance(request.user, Agent) and request.user.role == 'admin':
            users_stats = {
                'total_utilisateurs': Utilisateur.objects.count(),
                'total_agents': Agent.objects.count(),
                'new_this_month': Utilisateur.objects.filter(
                    date_creation__range=(start_date, end_date)
                ).count()
            }

        return Response({
            'period': {
                'start': start_date,
                'end': end_date
            },
            'demandes': demandes_stats,
            'users': users_stats,
            'last_updated': timezone.now()
        })



class ExportDataView(APIView):
    """
    Vue pour exporter les données en CSV ou JSON
    Permissions: Admin seulement
    Formats supportés: csv, json
    """
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer]
    
    def get(self, request, format=None):
        # Vérifier les permissions
        if not request.user.is_authenticated or not isinstance(request.user, Agent) or request.user.role != 'admin':
            return Response({"error": "Accès réservé aux administrateurs"}, status=403)

        # Récupérer le format demandé (csv par défaut)
        export_format = request.query_params.get('format', 'csv').lower()
        
        # Filtrer les données selon les paramètres
        queryset = Demande.objects.all()
        
        # Appliquer les filtres optionnels
        if start_date := request.query_params.get('start_date'):
            queryset = queryset.filter(date_demande__gte=start_date)
        if end_date := request.query_params.get('end_date'):
            queryset = queryset.filter(date_demande__lte=end_date)
        if commune_id := request.query_params.get('commune_id'):
            queryset = queryset.filter(commune_source_id=commune_id)

        # Préparer les données
        data = DemandeSerializer(queryset, many=True).data

        if export_format == 'json':
            return Response(data)
        
        # Générer le CSV
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="export_demandes_{datetime.now().strftime("%Y%m%d")}.csv"'
        
        writer = csv.writer(response)
        
        # Écrire l'en-tête
        if data:
            writer.writerow(data[0].keys())
        
        # Écrire les données
        for item in data:
            writer.writerow(item.values())
            
        return response



class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        
        try:
            user = Utilisateur.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            reset_url = f"{settings.FRONTEND_URL}/password-reset-confirm/{uid}/{token}/"
            
            subject = "Réinitialisation de votre mot de passe"
            message = render_to_string('email/password_reset_email.html', {
                'user': user,
                'reset_url': reset_url,
            })
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            return Response({"detail": "Email de réinitialisation envoyé"}, status=200)
        
        except Utilisateur.DoesNotExist:
            return Response({"detail": "Email non trouvé"}, status=400)







# Classes pour l'authentification et la gestion des utilisateurs
class EnregistrerUtilisateurView(generics.CreateAPIView):
    """Vue pour l'enregistrement d'un nouvel utilisateur"""
    queryset = Utilisateur.objects.all()
    permission_classes = [AllowAny]
    serializer_class = UtilisateurSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Créer une entrée de journal
            journal_data = {
                'type_action': 'creation',
                'description': f"Création du compte utilisateur {user.email}",
                'utilisateur': user.id,
                'adresse_ip': self.get_client_ip(request)
            }
            journal_serializer = JournalCreateSerializer(data=journal_data)
            if journal_serializer.is_valid():
                journal_serializer.save()

            # Créer une notification de bienvenue
            notif_data = {
                'titre': _("Bienvenue sur la plateforme"),
                'message': _(
                    "Votre compte a été créé avec succès. Vous pouvez maintenant effectuer des demandes d'extrait d'acte de naissance."),
                'type_notification': 'info',
                'utilisateur': user.id
            }
            notif_serializer = NotificationCreateSerializer(data=notif_data)
            if notif_serializer.is_valid():
                notif_serializer.save()

            return Response(
                {
                    "message": _("Compte créé avec succès."),
                    "user": serializer.data
                },
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UtilisateurLoginView(APIView):
    """Vue pour l'authentification d'un utilisateur"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            user = authenticate(request, username=email, password=password)

            if user is not None and isinstance(user, Utilisateur):
                login(request, user)

                # Générer les tokens JWT
                refresh = RefreshToken.for_user(user)

                # Créer une entrée de journal
                journal_data = {
                    'type_action': 'connexion',
                    'description': f"Connexion de l'utilisateur {user.email}",
                    'utilisateur': user.id,
                    'adresse_ip': self.get_client_ip(request)
                }
                journal_serializer = JournalCreateSerializer(data=journal_data)
                if journal_serializer.is_valid():
                    journal_serializer.save()

                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': UtilisateurSerializer(user).data
                })
            return Response(
                {"error": _("Identifiants invalides ou compte inactif.")},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class AgentLoginView(APIView):
    """Vue pour l'authentification d'un agent"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = AgentLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user = authenticate(request, username=username, password=password)

            if user is not None and isinstance(user, Agent):
                login(request, user)

                # Générer les tokens JWT
                refresh = RefreshToken.for_user(user)

                # Créer une entrée de journal
                journal_data = {
                    'type_action': 'connexion',
                    'description': f"Connexion de l'agent {user.username}",
                    'agent': user.id,
                    'adresse_ip': self.get_client_ip(request)
                }
                journal_serializer = JournalCreateSerializer(data=journal_data)
                if journal_serializer.is_valid():
                    journal_serializer.save()

                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': AgentSerializer(user).data
                })
            return Response(
                {"error": _("Identifiants invalides ou compte inactif.")},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class LogoutView(APIView):
    """Vue pour la déconnexion"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Créer une entrée de journal
        journal_data = {
            'type_action': 'deconnexion',
            'description': f"Déconnexion de l'utilisateur",
            'adresse_ip': self.get_client_ip(request)
        }

        if isinstance(request.user, Utilisateur):
            journal_data['utilisateur'] = request.user.id
        elif isinstance(request.user, Agent):
            journal_data['agent'] = request.user.id

        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        # Invalider le token refresh
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            pass

        logout(request)

        return Response({"message": _("Déconnexion réussie")})

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class PasswordChangeView(APIView):
    """Vue pour changer le mot de passe"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.validated_data['old_password']):
                return Response(
                    {"old_password": _("Mot de passe actuel incorrect.")},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user.set_password(serializer.validated_data['new_password'])
            user.save()

            # Créer une entrée de journal
            journal_data = {
                'type_action': 'modification',
                'description': "Changement de mot de passe",
                'adresse_ip': self.get_client_ip(request)
            }

            if isinstance(user, Utilisateur):
                journal_data['utilisateur'] = user.id
            elif isinstance(user, Agent):
                journal_data['agent'] = user.id

            journal_serializer = JournalCreateSerializer(data=journal_data)
            if journal_serializer.is_valid():
                journal_serializer.save()

            # Créer une notification
            notif_data = {
                'titre': _("Mot de passe modifié"),
                'message': _("Votre mot de passe a été modifié avec succès."),
                'type_notification': 'info'
            }

            if isinstance(user, Utilisateur):
                notif_data['utilisateur'] = user.id
            elif isinstance(user, Agent):
                notif_data['agent'] = user.id

            notif_serializer = NotificationCreateSerializer(data=notif_data)
            if notif_serializer.is_valid():
                notif_serializer.save()

            return Response({"message": _("Mot de passe modifié avec succès.")})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class PasswordResetRequestView(APIView):
    """Vue pour demander une réinitialisation de mot de passe"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            # Chercher l'utilisateur par email
            try:
                user = Utilisateur.objects.get(email=email)
                # Générer un token unique
                refresh = RefreshToken.for_user(user)
                token = str(refresh)

                # Créer le lien de réinitialisation
                reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"

                # Envoi de l'email
                subject = _("Réinitialisation de mot de passe")
                html_message = render_to_string('reset_password_email.html', {
                    'user': user,
                    'reset_link': reset_link
                })

                send_mail(
                    subject,
                    '',  # Message texte vide car on utilise uniquement le HTML
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    html_message=html_message,
                    fail_silently=False
                )

                return Response({
                    "message": _(
                        "Si un compte existe avec cette adresse email, un email de réinitialisation a été envoyé.")
                })
            except Utilisateur.DoesNotExist:
                # Simuler le succès même si l'utilisateur n'existe pas (sécurité)
                return Response({
                    "message": _(
                        "Si un compte existe avec cette adresse email, un email de réinitialisation a été envoyé.")
                })

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    """Vue pour confirmer la réinitialisation de mot de passe"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            password = serializer.validated_data['password']

            try:
                # Vérifier si le token est valide
                token_obj = RefreshToken(token)
                user_id = token_obj.payload.get('user_id')

                # Récupérer l'utilisateur
                user = Utilisateur.objects.get(id=user_id)

                # Changer le mot de passe
                user.set_password(password)
                user.save()

                # Créer une entrée de journal
                journal_data = {
                    'type_action': 'modification',
                    'description': "Réinitialisation de mot de passe",
                    'utilisateur': user.id
                }
                journal_serializer = JournalCreateSerializer(data=journal_data)
                if journal_serializer.is_valid():
                    journal_serializer.save()

                # Créer une notification
                notif_data = {
                    'titre': _("Mot de passe réinitialisé"),
                    'message': _("Votre mot de passe a été réinitialisé avec succès."),
                    'type_notification': 'info',
                    'utilisateur': user.id
                }
                notif_serializer = NotificationCreateSerializer(data=notif_data)
                if notif_serializer.is_valid():
                    notif_serializer.save()

                return Response({"message": _("Mot de passe réinitialisé avec succès.")})

            except Exception as e:
                return Response(
                    {"error": _("Token invalide ou expiré.")},
                    status=status.HTTP_400_BAD_REQUEST
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ViewSets pour les modèles
class UtilisateurViewSet(viewsets.ModelViewSet):
    """ViewSet pour la gestion des utilisateurs"""
    queryset = Utilisateur.objects.all()
    pagination_class = PermissionAwarePagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['email', 'nom', 'prenoms']
    ordering_fields = ['date_creation', 'nom', 'prenoms']

    def get_serializer_class(self):
        if self.action == 'list':
            return UtilisateurListSerializer
        elif self.action == 'update' or self.action == 'partial_update':
            return UtilisateurUpdateSerializer
        return UtilisateurSerializer

    def get_permissions(self):
        if self.action in ['update', 'partial_update']:
            permission_classes = [IsAuthenticated]
        elif self.action == 'retrieve':
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]


    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        """Récupérer les informations de l'utilisateur connecté"""
        serializer = UtilisateurSerializer(request.user)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def desactiver(self, request, pk=None):
        """Désactiver un compte utilisateur"""
        utilisateur = self.get_object()
        utilisateur.is_active = False
        utilisateur.save()

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'modification',
            'description': f"Désactivation du compte utilisateur {utilisateur.email}",
            'utilisateur': utilisateur.id,
            'adresse_ip': self.get_client_ip(request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        return Response({"message": _("Compte désactivé avec succès.")})

    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def reactiver(self, request, pk=None):
        """Réactiver un compte utilisateur (admin uniquement)"""
        utilisateur = self.get_object()
        utilisateur.is_active = True
        utilisateur.save()

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'modification',
            'description': f"Réactivation du compte utilisateur {utilisateur.email}",
            'agent': request.user.id,
            'utilisateur': utilisateur.id,
            'adresse_ip': self.get_client_ip(request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        return Response({"message": _("Compte réactivé avec succès.")})

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class CommuneViewSet(viewsets.ModelViewSet):
    """ViewSet pour la gestion des communes"""
    queryset = Commune.objects.all()
    pagination_class = CommunePagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['nom', 'region', 'type']
    ordering_fields = ['nom', 'region', 'type']

    def get_serializer_class(self):
        if self.action == 'list':
            return CommuneListSerializer
        return CommuneSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated]  # Déjà correct
        else:
            permission_classes = [AllowAny]  # Consultation libre
        return [permission() for permission in permission_classes]

    @action(detail=False, methods=['get'])
    def regions(self, request):
        """Récupérer la liste des régions disponibles"""
        regions = Commune.objects.values_list('region', flat=True).distinct()
        return Response(list(regions))

    @action(detail=False, methods=['get'])
    def by_region(self, request):
        """Récupérer les communes groupées par région"""
        region = request.query_params.get('region', None)
        if region:
            communes = Commune.objects.filter(region=region)
        else:
            communes = Commune.objects.all()

        serializer = CommuneListSerializer(communes, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        commune = serializer.save()

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'creation',
            'description': f"Création de la commune {commune.nom}",
            'adresse_ip': self.get_client_ip(self.request)
        }

        if isinstance(self.request.user, Agent):
            journal_data['agent'] = self.request.user.id

        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class AgentViewSet(viewsets.ModelViewSet):
    """ViewSet pour la gestion des agents"""
    queryset = Agent.objects.all()
    pagination_class = PermissionAwarePagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['username', 'email', 'nom', 'prenoms', 'matricule']
    ordering_fields = ['date_creation', 'nom', 'prenoms', 'commune_service__nom']

    def get_serializer_class(self):
        if self.action == 'list':
            return AgentListSerializer
        elif self.action in ['update', 'partial_update']:
            return AgentUpdateSerializer
        return AgentSerializer

    def get_permissions(self):
        if self.action in ['update', 'partial_update']:
            permission_classes = [IsAuthenticated]
        elif self.action in ['destroy', 'desactiver', 'reactiver']:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        """Filtrer les agents par commune pour les agents non-admin"""
        queryset = Agent.objects.all()

        if self.request.user.is_authenticated and isinstance(self.request.user, Agent):
            # Si c'est un agent non-admin, limiter aux agents de sa commune
            if self.request.user.role != 'admin':
                queryset = queryset.filter(commune_service=self.request.user.commune_service)

        return queryset

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        """Récupérer les informations de l'agent connecté"""
        serializer = AgentSerializer(request.user)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def desactiver(self, request, pk=None):
        """Désactiver un compte agent"""
        agent = self.get_object()
        agent.is_active = False
        agent.save()

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'modification',
            'description': f"Désactivation du compte agent {agent.username}",
            'agent': request.user.id,
            'adresse_ip': self.get_client_ip(request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        return Response({"message": _("Compte désactivé avec succès.")})

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def reactiver(self, request, pk=None):
        """Réactiver un compte agent"""
        agent = self.get_object()
        agent.is_active = True
        agent.save()

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'modification',
            'description': f"Réactivation du compte agent {agent.username}",
            'agent': request.user.id,
            'adresse_ip': self.get_client_ip(request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        return Response({"message": _("Compte réactivé avec succès.")})

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def by_commune(self, request):
        """Récupérer les agents par commune"""
        commune_id = request.query_params.get('commune_id', None)
        if commune_id:
            agents = Agent.objects.filter(commune_service_id=commune_id, is_active=True)
        else:
            agents = Agent.objects.filter(is_active=True)

        serializer = AgentListSerializer(agents, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        agent = serializer.save()

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'creation',
            'description': f"Création du compte agent {agent.username}",
            'agent': self.request.user.id,
            'adresse_ip': self.get_client_ip(self.request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class DemandeViewSet(viewsets.ModelViewSet):
    queryset = Demande.objects.all().order_by('-date_demande')
    pagination_class = DemandePagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['numero_demande', 'numero_acte', 'utilisateur__nom', 'utilisateur__prenoms']
    ordering_fields = ['date_demande', 'statut', 'commune_source__nom', 'commune_cible__nom']

    def get_serializer_class(self):
        if self.action == 'list':
            return DemandeListSerializer
        elif self.action == 'create':
            return DemandeCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return DemandeUpdateSerializer
        return DemandeSerializer

    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [IsAuthenticated]
        elif self.action in ['update', 'partial_update']:
            permission_classes = [IsAuthenticated]
        elif self.action == 'retrieve':
            permission_classes = [IsAuthenticated]
        elif self.action == 'list':
            permission_classes = [IsAuthenticated]
        elif self.action == 'prendre_en_charge':
            permission_classes = [IsAuthenticated]
        elif self.action == 'traiter':
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAdmin]
        return [permission() for permission in permission_classes]


    def list(self, request, *args, **kwargs):
        """Liste des demandes avec pagination personnalisée"""
        # Désactiver la pagination si paramètre 'all' est présent
        if request.query_params.get('all') == 'true':
            self.pagination_class = None
        
        return super().list(request, *args, **kwargs)


    def get_queryset(self):
        """Filtrer les demandes selon le type d'utilisateur"""
        queryset = Demande.objects.all()

        if self.request.user.is_authenticated:
            if isinstance(self.request.user, Utilisateur):
                # Utilisateur normal voit uniquement ses demandes
                queryset = queryset.filter(utilisateur=self.request.user)
            elif isinstance(self.request.user, Agent):
                if self.request.user.role != 'admin':
                    # Agent non-admin voit les demandes de sa commune
                    queryset = queryset.filter(commune_cible=self.request.user.commune_service)
                # Pour les admins, pas de filtrage spécifique

        # Filtres supplémentaires par statut, commune, etc.
        statut = self.request.query_params.get('statut', None)
        commune_id = self.request.query_params.get('commune_id', None)
        date_debut = self.request.query_params.get('date_debut', None)
        date_fin = self.request.query_params.get('date_fin', None)

        if statut:
            queryset = queryset.filter(statut=statut)
        if commune_id:
            queryset = queryset.filter(Q(commune_source_id=commune_id) | Q(commune_cible_id=commune_id))
        if date_debut:
            queryset = queryset.filter(date_demande__gte=date_debut)
        if date_fin:
            queryset = queryset.filter(date_demande__lte=date_fin)

        return queryset

    def perform_create(self, serializer):
        # Générer un numéro de demande unique
        prefix = "DEM"
        today = timezone.now().strftime('%Y%m%d')
        count = Demande.objects.filter(
            date_demande__year=timezone.now().year,
            date_demande__month=timezone.now().month,
            date_demande__day=timezone.now().day
        ).count() + 1

        numero_demande = f"{prefix}-{today}-{count:04d}"

        # Enregistrer la demande avec l'utilisateur connecté
        demande = serializer.save(
            utilisateur=self.request.user,
            numero_demande=numero_demande,
            statut='en_attente'
        )

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'creation',
            'description': f"Création de la demande {numero_demande}",
            'utilisateur': self.request.user.id,
            'demande': demande.id,
            'adresse_ip': self.get_client_ip(self.request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        # Créer une notification pour l'utilisateur
        notif_data = {
            'titre': _("Demande créée"),
            'message': _(
                f"Votre demande {numero_demande} a été créée avec succès et est en attente de traitement."),
            'type_notification': 'info',
            'utilisateur': self.request.user.id,
            'demande': demande.id
        }
        notif_serializer = NotificationCreateSerializer(data=notif_data)
        if notif_serializer.is_valid():
            notif_serializer.save()

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def prendre_en_charge(self, request, pk=None):
        """Action pour qu'un agent prenne en charge une demande"""
        demande = self.get_object()

        # Vérifier si la demande peut être prise en charge
        if demande.statut != 'en_attente':
            return Response(
                {"error": _("Cette demande ne peut pas être prise en charge car elle n'est pas en attente.")},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mettre à jour la demande
        demande.statut = 'en_cours'
        demande.agent_en_charge = request.user
        demande.date_prise_en_charge = timezone.now()
        demande.save()

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'modification',
            'description': f"Prise en charge de la demande {demande.numero_demande}",
            'agent': request.user.id,
            'demande': demande.id,
            'adresse_ip': self.get_client_ip(request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        # Créer une notification pour l'utilisateur
        notif_data = {
            'titre': _("Demande en traitement"),
            'message': _(f"Votre demande {demande.numero_demande} est maintenant en cours de traitement."),
            'type_notification': 'info',
            'utilisateur': demande.utilisateur.id,
            'demande': demande.id
        }
        notif_serializer = NotificationCreateSerializer(data=notif_data)
        if notif_serializer.is_valid():
            notif_serializer.save()

        return Response({
            "message": _("Demande prise en charge avec succès."),
            "demande": DemandeSerializer(demande).data
        })

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def traiter(self, request, pk=None):
        """Action pour traiter une demande (enregistrer ou rejeter)"""
        demande = self.get_object()
        action_type = request.data.get('action', None)

        # Vérifier si la demande est en cours de traitement
        if demande.statut != 'en_cours':
            return Response(
                {"error": _("Cette demande ne peut pas être traitée car elle n'est pas en cours.")},
                status=status.HTTP_400_BAD_REQUEST
            )

        if action_type == 'enregistrer':
            # Créer un enregistrement
            enregistrement_data = request.data.get('enregistrement', {})
            enregistrement_data['demande'] = demande.id
            enregistrement_data['agent'] = request.user.id

            enregistrement_serializer = EnregistrementSerializer(data=enregistrement_data)
            if enregistrement_serializer.is_valid():
                enregistrement = enregistrement_serializer.save()

                # Mettre à jour la demande
                demande.statut = 'traitee'
                demande.date_traitement = timezone.now()
                demande.save()

                # Créer une entrée de journal
                journal_data = {
                    'type_action': 'traitement',
                    'description': f"Traitement et enregistrement de la demande {demande.numero_demande}",
                    'agent': request.user.id,
                    'demande': demande.id,
                    'enregistrement': enregistrement.id,
                    'adresse_ip': self.get_client_ip(request)
                }
                journal_serializer = JournalCreateSerializer(data=journal_data)
                if journal_serializer.is_valid():
                    journal_serializer.save()

                # Créer une notification pour l'utilisateur
                notif_data = {
                    'titre': _("Demande traitée"),
                    'message': _(
                        f"Votre demande {demande.numero_demande} a été traitée. Vous pouvez maintenant procéder au paiement."),
                    'type_notification': 'success',
                    'utilisateur': demande.utilisateur.id,
                    'demande': demande.id,
                    'enregistrement': enregistrement.id
                }
                notif_serializer = NotificationCreateSerializer(data=notif_data)
                if notif_serializer.is_valid():
                    notif_serializer.save()

                return Response({
                    "message": _("Demande traitée avec succès."),
                    "demande": DemandeSerializer(demande).data,
                    "enregistrement": enregistrement_serializer.data
                })
            else:
                return Response(enregistrement_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        elif action_type == 'rejeter':
            # Créer un rejet
            rejet_data = request.data.get('rejet', {})
            rejet_data['demande'] = demande.id
            rejet_data['agent'] = request.user.id

            rejet_serializer = RejetCreateSerializer(data=rejet_data)
            if rejet_serializer.is_valid():
                rejet = rejet_serializer.save()

                # Mettre à jour la demande
                demande.statut = 'rejetee'
                demande.date_traitement = timezone.now()
                demande.save()

                # Créer une entrée de journal
                journal_data = {
                    'type_action': 'rejet',
                    'description': f"Rejet de la demande {demande.numero_demande}",
                    'agent': request.user.id,
                    'demande': demande.id,
                    'rejet': rejet.id,
                    'adresse_ip': self.get_client_ip(request)
                }
                journal_serializer = JournalCreateSerializer(data=journal_data)
                if journal_serializer.is_valid():
                    journal_serializer.save()

                # Créer une notification pour l'utilisateur
                notif_data = {
                    'titre': _("Demande rejetée"),
                    'message': _(f"Votre demande {demande.numero_demande} a été rejetée. Motif: {rejet.motif}"),
                    'type_notification': 'error',
                    'utilisateur': demande.utilisateur.id,
                    'demande': demande.id,
                    'rejet': rejet.id
                }
                notif_serializer = NotificationCreateSerializer(data=notif_data)
                if notif_serializer.is_valid():
                    notif_serializer.save()

                return Response({
                    "message": _("Demande rejetée."),
                    "demande": DemandeSerializer(demande).data,
                    "rejet": rejet_serializer.data
                })
            else:
                return Response(rejet_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(
                {"error": _("Action non reconnue. Utilisez 'enregistrer' ou 'rejeter'.")},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def statistiques(self, request):
        """Récupérer des statistiques sur les demandes"""
        # Détermination du queryset de base
        if isinstance(request.user, Utilisateur):
            queryset = Demande.objects.filter(utilisateur=request.user)
        elif isinstance(request.user, Agent):
            queryset = Demande.objects.filter(commune_cible=request.user.commune_service)
        if request.user.role == 'admin':
            queryset = Demande.objects.all()

        # Calcul des stats
        stats = {
            "total": queryset.count(),
            "en_attente": queryset.filter(statut='en_attente').count(),
            "en_cours": queryset.filter(statut='en_cours').count(),
            "traitees": queryset.filter(statut='traitee').count(),
            "rejetees": queryset.filter(statut='rejetee').count(),
            "payees": queryset.filter(statut='payee').count(),
            "livrees": queryset.filter(statut='livree').count(),
            "periode": {
                "debut": queryset.earliest('date_demande').date_demande if queryset.exists() else None,
                "fin": queryset.latest('date_demande').date_demande if queryset.exists() else None
            }
        }

        return Response(DemandeStatistiquesSerializer(stats).data)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class EnregistrementViewSet(viewsets.ModelViewSet):
    """ViewSet pour la gestion des enregistrements"""
    queryset = Enregistrement.objects.all()
    serializer_class = EnregistrementSerializer
    pagination_class = SmallResultsPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['numero_enregistrement', 'demande__numero_demande']
    ordering_fields = ['date_creation', 'demande__commune_cible__nom']

    def get_serializer_class(self):
        if self.action == 'list':
            return EnregistrementListSerializer
        return EnregistrementSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated]
        elif self.action in ['retrieve', 'list']:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAdmin]
        return [permission() for permission in permission_classes]


    def list(self, request, *args, **kwargs):
        """Liste des demandes avec pagination personnalisée"""
        # Désactiver la pagination si paramètre 'all' est présent
        if request.query_params.get('all') == 'true':
            self.pagination_class = None
        
        return super().list(request, *args, **kwargs)


    def get_queryset(self):
        queryset = Enregistrement.objects.all()
        user = self.request.user

        if user.is_authenticated:
            if user.role == 'user':  # Utilisateur standard
                # Un utilisateur ne devrait normalement pas voir les enregistrements directement
                return Enregistrement.objects.none()
                
            elif user.role == 'agent':  # Agent
                queryset = queryset.filter(agent=user)
                
            elif user.role == 'admin':  # Admin voit tout
                pass
                
        return queryset



    def perform_create(self, serializer):
        # Générer un numéro d'enregistrement unique
        prefix = "ENR"
        today = timezone.now().strftime('%Y%m%d')
        count = Enregistrement.objects.filter(
            date_creation__year=timezone.now().year,
            date_creation__month=timezone.now().month,
            date_creation__day=timezone.now().day
        ).count() + 1

        numero_enregistrement = f"{prefix}-{today}-{count:04d}"

        enregistrement = serializer.save(
            agent=self.request.user,
            numero_enregistrement=numero_enregistrement
        )

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'creation',
            'description': f"Création de l'enregistrement {numero_enregistrement}",
            'agent': self.request.user.id,
            'demande': enregistrement.demande.id,
            'enregistrement': enregistrement.id,
            'adresse_ip': self.get_client_ip(self.request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class PaiementViewSet(viewsets.ModelViewSet):
    """ViewSet pour la gestion des paiements"""
    queryset = Paiement.objects.all()
    pagination_class = CustomPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['reference_paiement', 'demande__numero_demande']
    ordering_fields = ['date_paiement', 'statut']

    def get_serializer_class(self):
        if self.action == 'create':
            return PaiementCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return PaiementUpdateSerializer
        return PaiementSerializer

    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [IsAuthenticated]  # Paiement = utilisateur concerné
        elif self.action in ['update', 'partial_update', 'verify']:
            permission_classes = [IsAuthenticated]  # Conserver
        elif self.action in ['retrieve', 'list']:
            permission_classes = [IsAuthenticated]  # Filtrage via get_queryset
        else:
            permission_classes = [IsAuthenticated, IsAdmin]  # Suppression réservée aux admins
        return [permission() for permission in permission_classes]


    def list(self, request, *args, **kwargs):
        """Liste des demandes avec pagination personnalisée"""
        # Désactiver la pagination si paramètre 'all' est présent
        if request.query_params.get('all') == 'true':
            self.pagination_class = None
        
        return super().list(request, *args, **kwargs)


    def get_queryset(self):
        """Filtrer les paiements selon le type d'utilisateur"""
        queryset = Paiement.objects.all()

        if self.request.user.is_authenticated:
            if isinstance(self.request.user, Utilisateur):
                # Utilisateur normal voit uniquement ses paiements
                queryset = queryset.filter(demande__utilisateur=self.request.user)
            elif isinstance(self.request.user, Agent):
                if self.request.user.role != 'admin':
                    # Agent non-admin voit les paiements de sa commune
                    queryset = queryset.filter(demande__commune_cible=self.request.user.commune_service)
                # Pour les admins, pas de filtrage spécifique

        return queryset

    def perform_create(self, serializer):
        # Générer une référence de paiement unique
        prefix = "PAY"
        today = timezone.now().strftime('%Y%m%d')
        count = Paiement.objects.filter(
            date_paiement__year=timezone.now().year,
            date_paiement__month=timezone.now().month,
            date_paiement__day=timezone.now().day
        ).count() + 1

        reference_paiement = f"{prefix}-{today}-{count:04d}"

        # Récupérer la demande
        demande_id = serializer.validated_data.get('demande').id
        demande = get_object_or_404(Demande, id=demande_id)

        # Vérifier que la demande est bien traitée
        if demande.statut != 'traitee':
            raise serializers.ValidationError(
                {"error": _("La demande doit être traitée avant de pouvoir effectuer un paiement.")})

        # Vérifier que l'utilisateur est bien propriétaire de la demande
        if demande.utilisateur != self.request.user:
            raise serializers.ValidationError(
                {"error": _("Vous n'êtes pas autorisé à effectuer un paiement pour cette demande.")})

        # Enregistrer le paiement
        paiement = serializer.save(
            reference_paiement=reference_paiement,
            statut='en_attente'
        )

        # Créer une entrée de journal
        journal_data = {
            'type_action': 'paiement',
            'description': f"Paiement initié pour la demande {demande.numero_demande}",
            'utilisateur': self.request.user.id,
            'demande': demande.id,
            'paiement': paiement.id,
            'adresse_ip': self.get_client_ip(self.request)
        }
        journal_serializer = JournalCreateSerializer(data=journal_data)
        if journal_serializer.is_valid():
            journal_serializer.save()

        # Créer une notification pour l'utilisateur
        notif_data = {
            'titre': _("Paiement initié"),
            'message': _(
                f"Votre paiement pour la demande {demande.numero_demande} a été initié et est en attente de confirmation."),
            'type_notification': 'info',
            'utilisateur': self.request.user.id,
            'demande': demande.id,
            'paiement': paiement.id
        }
        notif_serializer = NotificationCreateSerializer(data=notif_data)
        if notif_serializer.is_valid():
            notif_serializer.save()

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def verify(self, request, pk=None):
        """Action pour vérifier et confirmer un paiement"""
        paiement = self.get_object()
        action = request.data.get('action', None)

        if paiement.statut != 'en_attente':
            return Response(
                {"error": _("Ce paiement ne peut pas être vérifié car il n'est pas en attente.")},
                status=status.HTTP_400_BAD_REQUEST
            )

        if action == 'confirmer':
            # Confirmer le paiement
            paiement.statut = 'confirme'
            paiement.agent_verification = request.user
            paiement.date_verification = timezone.now()
            paiement.save()

            # Mettre à jour le statut de la demande
            demande = paiement.demande
            demande.statut = 'payee'
            demande.save()

            # Créer une entrée de journal
            journal_data = {
                'type_action': 'confirmation',
                'description': f"Confirmation du paiement {paiement.reference_paiement}",
                'agent': request.user.id,
                'demande': demande.id,
                'paiement': paiement.id,
                'adresse_ip': self.get_client_ip(request)
            }
            journal_serializer = JournalCreateSerializer(data=journal_data)
            if journal_serializer.is_valid():
                journal_serializer.save()

            # Créer une notification pour l'utilisateur
            notif_data = {
                'titre': _("Paiement confirmé"),
                'message': _(
                    f"Votre paiement pour la demande {demande.numero_demande} a été confirmé. Vous pouvez récupérer votre extrait d'acte de naissance à la mairie de {demande.commune_cible.nom}."),
                'type_notification': 'success',
                'utilisateur': demande.utilisateur.id,
                'demande': demande.id,
                'paiement': paiement.id
            }
            notif_serializer = NotificationCreateSerializer(data=notif_data)
            if notif_serializer.is_valid():
                notif_serializer.save()

            return Response({
                "message": _("Paiement confirmé avec succès."),
                "paiement": PaiementSerializer(paiement).data
            })

        elif action == 'rejeter':
            # Rejeter le paiement
            paiement.statut = 'rejete'
            paiement.agent_verification = request.user
            paiement.date_verification = timezone.now()
            paiement.commentaire = request.data.get('commentaire', '')
            paiement.save()

            # Créer une entrée de journal
            journal_data = {
                'type_action': 'rejet',
                'description': f"Rejet du paiement {paiement.reference_paiement}",
                'agent': request.user.id,
                'demande': paiement.demande.id,
                'paiement': paiement.id,
                'adresse_ip': self.get_client_ip(request)
            }
            journal_serializer = JournalCreateSerializer(data=journal_data)
            if journal_serializer.is_valid():
                journal_serializer.save()

            # Créer une notification pour l'utilisateur
            notif_data = {
                'titre': _("Paiement rejeté"),
                'message': _(
                    f"Votre paiement pour la demande {paiement.demande.numero_demande} a été rejeté. Motif: {paiement.commentaire}"),
                'type_notification': 'error',
                'utilisateur': paiement.demande.utilisateur.id,
                'demande': paiement.demande.id,
                'paiement': paiement.id
            }
            notif_serializer = NotificationCreateSerializer(data=notif_data)
            if notif_serializer.is_valid():
                notif_serializer.save()

            return Response({
                "message": _("Paiement rejeté."),
                "paiement": PaiementSerializer(paiement).data
            })
        else:
            return Response(
                {"error": _("Action non reconnue. Utilisez 'confirmer' ou 'rejeter'.")},
                status=status.HTTP_400_BAD_REQUEST
            )

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class RejetViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet pour la consultation des rejets"""
    queryset = Rejet.objects.all()
    serializer_class = RejetSerializer
    pagination_class = SmallResultsPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['demande__numero_demande', 'motif']
    ordering_fields = ['date_rejet']

    def get_permissions(self):
        if self.action in ['retrieve', 'list']:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAdminUser]
        return [permission() for permission in permission_classes]


    def list(self, request, *args, **kwargs):
        """Liste des demandes avec pagination personnalisée"""
        # Désactiver la pagination si paramètre 'all' est présent
        if request.query_params.get('all') == 'true':
            self.pagination_class = None
        
        return super().list(request, *args, **kwargs)


    def get_queryset(self):
        """Filtrer les rejets selon le type d'utilisateur"""
        queryset = Rejet.objects.all()

        if self.request.user.is_authenticated:
            if isinstance(self.request.user, Utilisateur):
                # Utilisateur normal voit uniquement ses rejets
                queryset = queryset.filter(demande__utilisateur=self.request.user)
            elif isinstance(self.request.user, Agent):
                if self.request.user.role != 'admin':
                    # Agent non-admin voit les rejets de sa commune
                    queryset = queryset.filter(demande__commune_cible=self.request.user.commune_service)
                # Pour les admins, pas de filtrage spécifique

        return queryset

class JournalViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet pour la consultation du journal d'activités"""
    queryset = Journal.objects.all().order_by('-date_action')
    serializer_class = JournalSerializer
    pagination_class = LargeResultsPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['description', 'type_action', 'adresse_ip']
    ordering_fields = ['date_action', 'type_action']

    def get_permissions(self):
        return [IsAuthenticated(), CanViewCommuneJournal()]


    def list(self, request, *args, **kwargs):
        """Liste des demandes avec pagination personnalisée"""
        # Désactiver la pagination si paramètre 'all' est présent
        if request.query_params.get('all') == 'true':
            self.pagination_class = None
        
        return super().list(request, *args, **kwargs)



    def get_queryset(self):
        """Filtrer le journal selon le type d'utilisateur"""
        queryset = Journal.objects.all()

        # Filtres supplémentaires
        utilisateur_id = self.request.query_params.get('utilisateur_id', None)
        agent_id = self.request.query_params.get('agent_id', None)
        demande_id = self.request.query_params.get('demande_id', None)
        type_action = self.request.query_params.get('type_action', None)
        date_debut = self.request.query_params.get('date_debut', None)
        date_fin = self.request.query_params.get('date_fin', None)

        if utilisateur_id:
            queryset = queryset.filter(utilisateur_id=utilisateur_id)
        if agent_id:
            queryset = queryset.filter(agent_id=agent_id)
        if demande_id:
            queryset = queryset.filter(demande_id=demande_id)
        if type_action:
            queryset = queryset.filter(type_action=type_action)
        if date_debut:
            queryset = queryset.filter(date_action__gte=date_debut)
        if date_fin:
            queryset = queryset.filter(date_action__lte=date_fin)

        return queryset


class NotificationViewSet(viewsets.ModelViewSet):
    queryset = Notification.objects.all().order_by('-date_creation')
    pagination_class = CustomPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['titre', 'message', 'type_notification']
    ordering_fields = ['date_creation', 'est_lu']

    def get_serializer_class(self):
        if self.action == 'create':
            return NotificationCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return NotificationUpdateSerializer
        return NotificationSerializer

    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [IsAuthenticated]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsAdmin]  # stricte
        elif self.action == 'marquer_lue':
            permission_classes = [IsAuthenticated]
        elif self.action == 'retrieve':
            permission_classes = [IsAuthenticated]
        elif self.action == 'list':
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAdmin]
        return [permission() for permission in permission_classes]


    def list(self, request, *args, **kwargs):
        """Liste des demandes avec pagination personnalisée"""
        # Désactiver la pagination si paramètre 'all' est présent
        if request.query_params.get('all') == 'true':
            self.pagination_class = None
        
        return super().list(request, *args, **kwargs)


    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Notification.objects.none()
        
        # Utilisateurs normaux voient seulement leurs notifications
        queryset = Notification.objects.filter(utilisateur=user)
        
        # Admins et superviseurs voient toutes les notifications
        if user.role in [Utilisateur.RoleChoices.ADMIN, Utilisateur.RoleChoices.SUPERVISOR]:
            queryset = Notification.objects.all()
        
        return queryset

    @action(detail=True, methods=['post'])
    def marquer_lue(self, request, pk=None):
        """Marquer une notification comme lue"""
        notification = self.get_object()
        
        # Vérifier que l'utilisateur est bien le destinataire
        if notification.utilisateur != request.user:
            return Response(
                {"detail": "Vous n'avez pas la permission d'effectuer cette action."},
                status=status.HTTP_403_FORBIDDEN
            )
            
        notification.est_lu = True
        notification.date_lecture = timezone.now()
        notification.save()
        
        return Response(
            {"detail": "Notification marquée comme lue."},
            status=status.HTTP_200_OK
        )

    def perform_create(self, serializer):
        """Ajoute des logs lors de la création"""
        notification = serializer.save()
        
        # Journalisation
        journal_data = {
            'type_action': 'creation',
            'description': f"Création de notification pour {notification.utilisateur}",
            'adresse_ip': self.get_client_ip(self.request)
        }
        
        if isinstance(self.request.user, Agent):
            journal_data['agent'] = self.request.user.id
        else:
            journal_data['utilisateur'] = self.request.user.id
            
        Journal.objects.create(**journal_data)
