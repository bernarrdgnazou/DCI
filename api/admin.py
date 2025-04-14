from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse
from django import forms
from django.db.models import Q
from django.contrib.admin.models import LogEntry
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import (
    UserChangeForm,
    UserCreationForm,
    AdminPasswordChangeForm
)
from django.utils import timezone
from datetime import timedelta
from .models import (
    Utilisateur,
    Commune,
    Agent,
    Demande,
    Enregistrement,
    Paiement,
    Rejet,
    Journal,
    Notification,
)

# ==================== FILTRES PERSONNALISÉS ====================
class StatutDemandeFilter(admin.SimpleListFilter):
    title = _('Statut avancé')
    parameter_name = 'statut_avance'

    def lookups(self, request, model_admin):
        return (
            ('en_retard', _('En retard')),
            ('a_valider', _('À valider')),
            ('urgent', _('Urgent')),
        )

    def queryset(self, request, queryset):
        if self.value() == 'en_retard':
            return queryset.filter(
                Q(statut='en_attente') & Q(date_demande__lt=timezone.now()-timedelta(days=7)))
        elif self.value() == 'a_valider':
            return queryset.filter(statut='en_attente')
        elif self.value() == 'urgent':
            return queryset.filter(Q(statut='en_attente') & Q(utilisateur__isnull=False))

# ==================== INLINES ====================
class PaiementInline(admin.StackedInline):
    model = Paiement
    extra = 0
    fields = ('reference', 'montant', 'methode', 'statut', 'telephone', 'id_transaction', 'date_paiement')
    readonly_fields = ('reference', 'date_paiement')
    classes = ('collapse',)

# ==================== ADMINISTRATION DES MODÈLES ====================



class UtilisateurAdminForm(forms.ModelForm):
    """Formulaire personnalisé pour l'administration des utilisateurs."""
    class Meta:
        model = Utilisateur
        fields = '__all__'
        labels = {
            'last_name': _('Nom'),
            'first_name': _('Prénom'),
            'date_joined': _('Date de création'),
            'last_login': _('Dernière connexion')
        }


@admin.register(Utilisateur)
class UtilisateurAdmin(UserAdmin):
    """Administration personnalisée pour le modèle Utilisateur."""
    form = UtilisateurAdminForm
    
    # Configuration de l'affichage
    list_display = (
        'id_display',
        'email',
        'username',
        'nom_complet',
        'sexe_display',
        'telephone',
        'status_actif',
        'is_staff',
        'is_superuser',
        'date_creation_display',
        'last_login_display',
        'groupes_list'
    )
    
    list_display_links = ('id_display', 'email', 'username')
    list_filter = (
        'is_active',
        'is_staff',
        'is_superuser',
        'sexe',
        'groups',
        'date_joined'
    )
    search_fields = (
        'email',
        'username',
        'last_name',
        'first_name',
        'telephone',
        'id'
    )
    filter_horizontal = ('groups', 'user_permissions')
    readonly_fields = (
        'last_login_display',
        'date_creation_display',
        'date_modification_display'
    )
    ordering = ('-date_joined',)
    actions = ['activate_users', 'deactivate_users']

    # Organisation des champs
    fieldsets = (
        (None, {
            'fields': ('email', 'username', 'password')
        }),
        (_('Informations personnelles'), {
            'fields': (
                ('last_name', 'first_name'),
                'sexe',
                'telephone'
            )
        }),
        (_('Permissions'), {
            'fields': (
                'is_active',
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions'
            ),
            'classes': ('collapse',)
        }),
        (_('Historique'), {
            'fields': (
                'last_login_display',
                'date_creation_display',
                'date_modification_display'
            ),
            'classes': ('collapse',)
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email',
                'username',
                'password1',
                'password2',
                ('last_name', 'first_name'),
                'sexe',
                'telephone',
                'is_active',
                'is_staff',
                'groups'
            ),
        }),
    )

    # Méthodes d'affichage personnalisées
    def id_display(self, obj):
        """Affiche les 8 premiers caractères de l'ID."""
        return str(obj.id)[:8]
    id_display.short_description = 'ID'
    id_display.admin_order_field = 'id'

    def nom_complet(self, obj):
        """Affiche le nom complet de l'utilisateur."""
        if obj.last_name and obj.first_name:
            return f"{obj.last_name} {obj.first_name}"
        elif obj.last_name:
            return obj.last_name
        elif obj.first_name:
            return obj.first_name
        return "-"
    nom_complet.short_description = _('Nom complet')
    nom_complet.admin_order_field = 'last_name'

    def sexe_display(self, obj):
        """Affiche la valeur lisible du sexe."""
        return dict(Utilisateur.SexeChoices.choices).get(obj.sexe, "-")
    sexe_display.short_description = _('Sexe')
    sexe_display.admin_order_field = 'sexe'

    def status_actif(self, obj):
        """Affiche un indicateur visuel pour le statut actif/inactif."""
        return format_html(
            '<span style="color: {};">{}</span>',
            'green' if obj.is_active else 'red',
            '✔' if obj.is_active else '✖'
        )
    status_actif.short_description = _('Statut')
    status_actif.admin_order_field = 'is_active'

    def date_creation_display(self, obj):
        """Formatte la date de création."""
        return obj.date_joined.strftime("%d/%m/%Y %H:%M") if obj.date_joined else "-"
    date_creation_display.short_description = _('Date création')
    date_creation_display.admin_order_field = 'date_joined'

    def date_modification_display(self, obj):
        """Formatte la date de modification."""
        return obj.date_modification.strftime("%d/%m/%Y %H:%M") if hasattr(obj, 'date_modification') and obj.date_modification else "-"
    date_modification_display.short_description = _('Dernière modification')
    date_modification_display.admin_order_field = 'date_modification'

    def last_login_display(self, obj):
        """Formatte la date de dernière connexion."""
        return obj.last_login.strftime("%d/%m/%Y %H:%M") if obj.last_login else _("Jamais")
    last_login_display.short_description = _('Dernière connexion')
    last_login_display.admin_order_field = 'last_login'

    def groupes_list(self, obj):
        """Affiche les groupes avec des liens vers leur page d'administration."""
        groups = obj.groups.all()
        if not groups:
            return "-"
        
        links = []
        for group in groups:
            url = reverse('admin:auth_group_change', args=[group.id])
            links.append(f'<a href="{url}">{escape(group.name)}</a>')
        return format_html(', '.join(links))
    groupes_list.short_description = _('Groupes')

    # Actions personnalisées
    def activate_users(self, request, queryset):
        """Active les utilisateurs sélectionnés."""
        updated = queryset.update(is_active=True)
        self.message_user(
            request, 
            ngettext(
                "%d utilisateur activé avec succès.",
                "%d utilisateurs activés avec succès.",
                updated
            ) % updated,
            messages.SUCCESS
        )
    activate_users.short_description = _("Activer les utilisateurs sélectionnés")

    def deactivate_users(self, request, queryset):
        """Désactive les utilisateurs sélectionnés."""
        # Empêcher la désactivation de son propre compte
        if request.user.pk in queryset.values_list('pk', flat=True):
            self.message_user(
                request, 
                _("Vous ne pouvez pas désactiver votre propre compte."),
                messages.ERROR
            )
            return
            
        updated = queryset.update(is_active=False)
        self.message_user(
            request, 
            ngettext(
                "%d utilisateur désactivé avec succès.",
                "%d utilisateurs désactivés avec succès.",
                updated
            ) % updated,
            messages.SUCCESS
        )
    deactivate_users.short_description = _("Désactiver les utilisateurs sélectionnés")

    # Optimisation des requêtes
    def get_queryset(self, request):
        """Optimise les requêtes en préchargeant les relations."""
        return super().get_queryset(request).prefetch_related('groups')

    def get_form(self, request, obj=None, **kwargs):
        """Personnalise les labels des champs du formulaire."""
        form = super().get_form(request, obj, **kwargs)
        if not form.base_fields:
            return form
            
        field_labels = {
            'last_name': _('Nom'),
            'first_name': _('Prénom'),
            'last_login': _('Dernière connexion'),
            'date_joined': _('Date de création'),
            'email': _('Adresse e-mail'),
            'is_active': _('Actif'),
            'is_staff': _('Statut staff'),
            'is_superuser': _('Statut superutilisateur'),
            'groups': _('Groupes'),
            'user_permissions': _('Permissions')
        }
        
        for field, label in field_labels.items():
            if field in form.base_fields:
                form.base_fields[field].label = label
                
        return form
        
    def save_model(self, request, obj, form, change):
        """Sauvegarde le modèle avec traçabilité des modifications."""
        if not change:
            # Si c'est une création
            obj.created_by = request.user.username
        else:
            # Si c'est une modification
            obj.modified_by = request.user.username
            
        super().save_model(request, obj, form, change)



@admin.register(Commune)
class CommuneAdmin(admin.ModelAdmin):
    list_display = ('nom', 'type', 'region', 'telephone', 'email', 
                   'adresse_postale', 'signature', 'date_creation')
    list_filter = ('type', 'region')
    search_fields = ('nom', 'region', 'telephone', 'email')
    readonly_fields = ('date_creation', 'date_modification')

    fieldsets = (
        (None, {
            'fields': ('nom', 'type', 'region')
        }),
        (_('Coordonnées'), {
            'fields': ('adresse_postale', 'telephone', 'email')
        }),
        (_('Signature'), {
            'fields': ('signature',)
        }),
        (_('Dates'), {
            'fields': ('date_creation', 'date_modification'),
            'classes': ('collapse',)
        }),
    )



class AgentAdminForm(forms.ModelForm):
    class Meta:
        model = Agent
        fields = '__all__'
        labels = {
            'last_name': _('Nom'),
            'first_name': _('Prénom'),
            'last_login': _('Dernière connexion')
        }

@admin.register(Agent)
class AgentAdmin(UserAdmin):

    form = AgentAdminForm
    
    # Configuration de l'affichage
    list_display = (
        'email',
        'username',
        'matricule',
        'get_nom_complet',
        'commune_link',
        'role_display',
        'poste',
        'sexe',
        'telephone',
        'status',
        'is_staff',
        'is_superuser',
        'date_joined_display'
    )
    
    list_filter = (
        'is_active',
        'is_staff',
        'is_superuser',
        'role',
        'commune_service',
        'groups'
    )
    
    search_fields = (
        'email',
        'username',
        'matricule',
        'last_name',
        'first_name',
        'telephone',
        'poste'
    )
    
    filter_horizontal = ('groups', 'user_permissions')
    readonly_fields = (
        'last_login_display',
        'password_display'
    )
    
    # Organisation des champs
    fieldsets = (
        (None, {
            'fields': ('email', 'username', 'password_display')
        }),
        (_('Informations personnelles'), {
            'fields': (
                'last_name',
                'first_name',
                'sexe',
                'matricule',
                'telephone',
                'photo'
            )
        }),
        (_('Informations professionnelles'), {
            'fields': (
                'commune_service',
                'poste',
                'role',
                'status'
            )
        }),
        (_('Permissions'), {
            'fields': (
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions'
            ),
            'classes': ('collapse',)
        }),
        (_('Historique'), {
            'fields': (
                'last_login_display',
            ),
            'classes': ('collapse',)
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email',
                'username',
                'password1',
                'password2',
                ('last_name', 'first_name'),
                'sexe',
                'matricule',
                'telephone',
                'photo',
                'commune_service',
                'poste',
                'role',
                'status',
                'is_staff',
                'is_superuser',
                'groups'
            ),
        }),
    )

    # Méthodes d'affichage personnalisées
    def get_nom_complet(self, obj):
        return f"{obj.last_name} {obj.first_name}" if obj.last_name or obj.first_name else "-"
    get_nom_complet.short_description = _('Nom complet')
    get_nom_complet.admin_order_field = 'last_name'

    def date_joined_display(self, obj):
        return obj.date_joined.strftime("%d/%m/%Y %H:%M") if hasattr(obj, 'date_joined') and obj.date_joined else "-"
    date_joined_display.short_description = _('Date de création')

    def last_login_display(self, obj):
        return obj.last_login.strftime("%d/%m/%Y %H:%M") if obj.last_login else "-"
    last_login_display.short_description = _('Dernière connexion')

    def commune_link(self, obj):
        if obj.commune_service:
            url = reverse('admin:api_commune_change', args=[obj.commune_service.id])
            return format_html('<a href="{}">{}</a>', url, obj.commune_service.nom)
        return "-"
    commune_link.short_description = _('Commune')

    def role_display(self, obj):
        return obj.get_role_display()
    role_display.short_description = _('Rôle')

    def password_display(self, obj):
        return "********" if obj.password else "Non défini"
    password_display.short_description = _('Mot de passe')

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'last_name' in form.base_fields:
            form.base_fields['last_name'].label = _('Nom')
        if 'first_name' in form.base_fields:
            form.base_fields['first_name'].label = _('Prénom')
        if 'last_login' in form.base_fields:
            form.base_fields['last_login'].label = _('Dernière connexion')
        return form



@admin.register(Demande)
class DemandeAdmin(admin.ModelAdmin):
    list_display = ('numero_demande', 'utilisateur_link', 'communes_display',
                   'statut_badge', 'quantite', 'agent_en_charge', 'date_demande')
    list_filter = (StatutDemandeFilter, 'statut', 'commune_source', 'date_demande')
    search_fields = ('numero_demande', 'utilisateur__nom', 'utilisateur__email', 'numero_acte')
    inlines = (PaiementInline,)
    readonly_fields = ('date_demande', 'date_modification')

    fieldsets = (
        (None, {
            'fields': ('numero_demande', 'utilisateur')
        }),
        (_('Détails de la demande'), {
            'fields': ('commune_source', 'commune_cible', 'numero_acte', 'date_etablissement', 'quantite')
        }),
        (_('Traitement'), {
            'fields': ('statut', 'agent_en_charge', 'commentaires')
        }),
        (_('Dates'), {
            'fields': ('date_demande', 'date_modification'),
            'classes': ('collapse',)
        }),
    )

    def utilisateur_link(self, obj):
        url = reverse('admin:api_utilisateur_change', args=[obj.utilisateur.id])
        return format_html('<a href="{}">{}</a>', url, obj.utilisateur)
    utilisateur_link.short_description = _('Demandeur')

    def statut_badge(self, obj):
        colors = {
            'en_attente': 'gray',
            'en_cours': 'orange',
            'rejete': 'red',
            'echec': 'darkred',
            'succes': 'green'
        }
        return format_html(
            '<span style="background-color:{};color:white;padding:3px 8px;border-radius:10px;">{}</span>',
            colors.get(obj.statut, 'gray'),
            obj.get_statut_display()
        )
    statut_badge.short_description = _('Statut')

    def communes_display(self, obj):
        return f"{obj.commune_source} → {obj.commune_cible}"
    communes_display.short_description = _('Communes')

@admin.register(Enregistrement)
class EnregistrementAdmin(admin.ModelAdmin):
    list_display = ('numero_acte', 'nom_enfant', 'date_naissance', 
                   'lieu_naissance', 'date_creation')
    search_fields = ('numero_acte', 'nom_enfant', 'prenoms_enfant', 'demande__numero_demande')
    list_filter = ('date_acte', 'date_enregistrement')
    readonly_fields = ('date_creation', 'date_modification')

    fieldsets = (
        (_('Références'), {
            'fields': ('agent',)
        }),
        (_('Informations sur l\'acte'), {
            'fields': ('numero_acte', 'date_acte', 'date_enregistrement')
        }),
        (_('Informations sur l\'enfant'), {
            'fields': ('nom_enfant', 'prenoms_enfant', 'date_naissance', 
                      'heure_naissance', 'lieu_naissance', 'sexe')
        }),
        (_('Informations sur le père'), {
            'fields': ('nom_pere', 'prenoms_pere', 'nationalite_pere',
                      'profession_pere', 'domicile_pere')
        }),
        (_('Informations sur la mère'), {
            'fields': ('nom_mere', 'prenoms_mere', 'nationalite_mere',
                      'profession_mere', 'domicile_mere')
        }),
        (_('Détails administratifs'), {
            'fields': ('date_delivrance', 'lieu_delivrance',
                      'nom_officier_etat_civil', 'signature_officier',
                      'fonction_officier', 'sceau_officiel',
                      'mentions_marginales')
        }),
        (_('Dates'), {
            'fields': ('date_creation', 'date_modification'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Paiement)
class PaiementAdmin(admin.ModelAdmin):
    list_display = ('reference', 'demande_link', 'montant', 'methode', 
                   'statut', 'telephone', 'id_transaction', 'date_paiement')
    list_filter = ('methode', 'statut')
    search_fields = ('reference', 'demande__numero_demande', 'id_transaction')
    readonly_fields = ('reference', 'date_paiement')

    fieldsets = (
        (None, {
            'fields': ('demande', 'reference', 'montant', 'methode')
        }),
        (_('Détails du paiement'), {
            'fields': ('statut', 'telephone', 'id_transaction')
        }),
        (_('Dates'), {
            'fields': ('date_paiement',),
            'classes': ('collapse',)
        }),
    )

    def demande_link(self, obj):
        url = reverse('admin:api_demande_change', args=[obj.demande.id])
        return format_html('<a href="{}">{}</a>', url, obj.demande.numero_demande)
    demande_link.short_description = _('Demande')

@admin.register(Rejet)
class RejetAdmin(admin.ModelAdmin):
    list_display = ('demande_link', 'agent_link', 'motif_court', 
                   'date_rejet', 'delais_recours')
    search_fields = ('demande__numero_demande', 'agent__nom', 'motif')
    readonly_fields = ('date_rejet',)

    fieldsets = (
        (None, {
            'fields': ('demande', 'agent')
        }),
        (_('Détails du rejet'), {
            'fields': ('motif', 'procedure_recours')
        }),
        (_('Délais'), {
            'fields': ('delais_recours',)
        }),
        (_('Dates'), {
            'fields': ('date_rejet',),
            'classes': ('collapse',)
        }),
    )

    def demande_link(self, obj):
        url = reverse('admin:api_demande_change', args=[obj.demande.id])
        return format_html('<a href="{}">{}</a>', url, obj.demande.numero_demande)
    demande_link.short_description = _('Demande')

    def agent_link(self, obj):
        url = reverse('admin:api_agent_change', args=[obj.agent.id])
        return format_html('<a href="{}">{}</a>', url, obj.agent)
    agent_link.short_description = _('Agent')

    def motif_court(self, obj):
        return obj.motif[:50] + "..." if len(obj.motif) > 50 else obj.motif
    motif_court.short_description = _('Motif')


@admin.register(Journal)
class JournalAdmin(admin.ModelAdmin):
    list_display = ('date_action', 'type_action', 'utilisateur_with_role',
                   'description_courte', 'adresse_ip', 'demande_link')

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('utilisateur')

    def role_display(self, obj):
        if obj.utilisateur:
            return obj.utilisateur.get_role_display()
        return "-"
    role_display.short_description = _('Rôle')
    list_filter = ('type_action', 'date_action')
    search_fields = ('description', 'utilisateur__last_name', 'utilisateur__first_name', 'adresse_ip')
    readonly_fields = ('date_action',)

    fieldsets = (
        (None, {
            'fields': ('type_action', 'description')
        }),
        (_('Acteurs'), {
            'fields': ('utilisateur',)  # Removed 'agent' from here
        }),
        (_('Objet concerné'), {
            'fields': ('demande',)
        }),
        (_('Informations techniques'), {
            'fields': ('adresse_ip',)
        }),
        (_('Dates'), {
            'fields': ('date_action',),
            'classes': ('collapse',)
        }),
    )

    def utilisateur_with_role(self, obj):
        if obj.utilisateur:
            url = reverse('admin:api_utilisateur_change', args=[obj.utilisateur.id])
            role = ""
            if hasattr(obj.utilisateur, 'agent'):
                role = " (Agent)"
            return format_html('<a href="{}">{}{}</a>', url, obj.utilisateur, role)
        return "-"
    utilisateur_with_role.short_description = _('Utilisateur')

    def description_courte(self, obj):
        return obj.description[:50] + "..." if len(obj.description) > 50 else obj.description
    description_courte.short_description = _('Description')

    def demande_link(self, obj):
        if obj.demande:
            url = reverse('admin:api_demande_change', args=[obj.demande.id])
            return format_html('<a href="{}">{}</a>', url, obj.demande.numero_demande)
        return "-"
    demande_link.short_description = _('Demande')


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('titre', 'type_notification', 'destinataire', 
                   'est_lu', 'date_creation', 'demande_link')
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('utilisateur')

    def is_agent(self, obj):
        return hasattr(obj.utilisateur, 'agent') if obj.utilisateur else False
    is_agent.boolean = True
    is_agent.short_description = _('Est agent')
    list_filter = ('type_notification', 'est_lu')
    search_fields = ('titre', 'message', 'utilisateur__last_name', 'utilisateur__first_name')  # Removed agent__nom
    readonly_fields = ('date_creation',)

    fieldsets = (
        (None, {
            'fields': ('titre', 'message', 'type_notification')
        }),
        (_('Destinataire'), {
            'fields': ('utilisateur',)  # Removed agent, added comma to make it a tuple
        }),
        (_('Objet concerné'), {
            'fields': ('demande',)
        }),
        (_('Statut'), {
            'fields': ('est_lu', 'date_lecture')
        }),
        (_('Dates'), {
            'fields': ('date_creation',),
            'classes': ('collapse',)
        }),
    )

    def destinataire(self, obj):
        if obj.utilisateur:
            url = reverse('admin:api_utilisateur_change', args=[obj.utilisateur.id])
            # Check if the user is an agent
            role = ""
            if hasattr(obj.utilisateur, 'agent'):
                role = " (Agent)"
            return format_html('<a href="{}">{}{}</a>', url, obj.utilisateur, role)
        return "-"
    destinataire.short_description = _('Destinataire')

    def demande_link(self, obj):
        if obj.demande:
            url = reverse('admin:api_demande_change', args=[obj.demande.id])
            return format_html('<a href="{}">{}</a>', url, obj.demande.numero_demande)
        return "-"
    demande_link.short_description = _('Demande')



@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('action_time', 'user', 'content_type', 'object_repr', 'action_flag')
    list_filter = ('action_flag', 'content_type')
    search_fields = ('user__username', 'object_repr')
    date_hierarchy = 'action_time'
    readonly_fields = ('action_time',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False