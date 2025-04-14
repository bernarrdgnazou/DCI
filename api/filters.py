from django.utils.translation import gettext_lazy as _
from django_filters import rest_framework as filters
import django_filters
from datetime import datetime, timedelta
from django.db.models import Q

from .models import (
    Utilisateur, Agent, Commune, Demande, 
    Enregistrement, Paiement, Rejet, Journal, 
    Notification
)


class UtilisateurFilter(filters.FilterSet):
    """Filtres pour le modèle Utilisateur"""
    nom_complet = filters.CharFilter(method='filter_nom_complet', label=_("Nom complet"))
    role = filters.ChoiceFilter(choices=Utilisateur.RoleChoices.choices, label=_("Rôle"))
    date_creation_min = filters.DateTimeFilter(field_name='date_joined', lookup_expr='gte', label=_("Date création après"))
    date_creation_max = filters.DateTimeFilter(field_name='date_joined', lookup_expr='lte', label=_("Date création avant"))
    est_actif = filters.BooleanFilter(field_name='is_active', label=_("Est actif"))

    def filter_nom_complet(self, queryset, name, value):
        """Filtre sur le nom complet (prénom + nom)"""
        # Séparation de la valeur reçue en mots
        terms = value.split()
        # Création d'un Q object pour chaque terme
        q_objects = Q()
        for term in terms:
            q_objects |= (
                Q(first_name__icontains=term) | 
                Q(last_name__icontains=term)
            )
        return queryset.filter(q_objects)

    class Meta:
        model = Utilisateur
        fields = {
            'username': ['exact', 'icontains'],
            'email': ['exact', 'icontains'],
            'first_name': ['icontains'],
            'last_name': ['icontains'],
            'sexe': ['exact'],
            'telephone': ['exact', 'icontains'],
        }


class AgentFilter(filters.FilterSet):
    """Filtres pour le modèle Agent"""
    nom_complet = filters.CharFilter(method='filter_nom_complet', label=_("Nom complet"))
    commune = filters.ModelChoiceFilter(
        queryset=Commune.objects.all(), 
        field_name='commune_service',
        label=_("Commune de service")
    )
    statut = filters.ChoiceFilter(
        choices=Agent.IsActiveItems.choices,
        label=_("Statut de l'agent")
    )
    role = filters.ChoiceFilter(
        choices=Utilisateur.RoleChoices.choices,
        label=_("Rôle de l'agent")
    )

    def filter_nom_complet(self, queryset, name, value):
        """Filtre sur le nom complet (prénom + nom)"""
        terms = value.split()
        q_objects = Q()
        for term in terms:
            q_objects |= (
                Q(first_name__icontains=term) | 
                Q(last_name__icontains=term)
            )
        return queryset.filter(q_objects)

    class Meta:
        model = Agent
        fields = {
            'matricule': ['exact', 'icontains'],
            'email': ['exact', 'icontains'],
            'poste': ['exact', 'icontains'],
        }


class CommuneFilter(filters.FilterSet):
    """Filtres pour le modèle Commune"""
    region = filters.CharFilter(lookup_expr='icontains', label=_("Région"))
    type = filters.ChoiceFilter(choices=Commune.TypeItems.choices, label=_("Type de commune"))
    date_creation_min = filters.DateTimeFilter(field_name='date_creation', lookup_expr='gte', label=_("Créée après"))
    date_creation_max = filters.DateTimeFilter(field_name='date_creation', lookup_expr='lte', label=_("Créée avant"))

    class Meta:
        model = Commune
        fields = {
            'nom': ['exact', 'icontains'],
            'email': ['exact', 'icontains'],
            'telephone': ['exact', 'icontains'],
        }


class DemandeFilter(filters.FilterSet):
    """Filtres pour le modèle Demande"""
    utilisateur = filters.ModelChoiceFilter(
        queryset=Utilisateur.objects.all(),
        label=_("Utilisateur")
    )
    statut = filters.ChoiceFilter(
        choices=Demande.StatutDemande.choices,
        label=_("Statut")
    )
    date_demande_min = filters.DateTimeFilter(field_name='date_demande', lookup_expr='gte', label=_("Après le"))
    date_demande_max = filters.DateTimeFilter(field_name='date_demande', lookup_expr='lte', label=_("Avant le"))
    commune_source = filters.ModelChoiceFilter(
        queryset=Commune.objects.all(),
        label=_("Commune source")
    )
    commune_cible = filters.ModelChoiceFilter(
        queryset=Commune.objects.all(),
        label=_("Commune cible")
    )
    agent_en_charge = filters.ModelChoiceFilter(
        queryset=Agent.objects.all(),
        label=_("Agent en charge")
    )
    numero_demande = filters.CharFilter(lookup_expr='icontains', label=_("Numéro de demande"))
    numero_acte = filters.CharFilter(lookup_expr='icontains', label=_("Numéro d'acte"))
    
    # Filtres pour les demandes récentes
    recentes = filters.BooleanFilter(method='filter_recentes', label=_("Demandes récentes"))
    
    def filter_recentes(self, queryset, name, value):
        """Filtre pour les demandes datant de moins d'une semaine"""
        if value:
            date_limite = datetime.now() - timedelta(days=7)
            return queryset.filter(date_demande__gte=date_limite)
        return queryset

    class Meta:
        model = Demande
        fields = {
            'quantite': ['exact', 'gt', 'lt'],
            'date_etablissement': ['exact', 'year', 'month'],
        }


class EnregistrementFilter(filters.FilterSet):
    """Filtres pour le modèle Enregistrement"""
    agent = filters.ModelChoiceFilter(
        queryset=Agent.objects.all(),
        label=_("Agent")
    )
    nom_enfant = filters.CharFilter(lookup_expr='icontains', label=_("Nom de l'enfant"))
    prenoms_enfant = filters.CharFilter(lookup_expr='icontains', label=_("Prénoms de l'enfant"))
    date_naissance_min = filters.DateFilter(field_name='date_naissance', lookup_expr='gte', label=_("Né(e) après"))
    date_naissance_max = filters.DateFilter(field_name='date_naissance', lookup_expr='lte', label=_("Né(e) avant"))
    sexe = filters.CharFilter(lookup_expr='iexact', label=_("Sexe"))
    numero_acte = filters.CharFilter(lookup_expr='icontains', label=_("Numéro d'acte"))
    lieu_naissance = filters.CharFilter(lookup_expr='icontains', label=_("Lieu de naissance"))
    date_acte_min = filters.DateFilter(field_name='date_acte', lookup_expr='gte', label=_("Date acte après"))
    date_acte_max = filters.DateFilter(field_name='date_acte', lookup_expr='lte', label=_("Date acte avant"))
    
    # Recherche parents
    nom_pere = filters.CharFilter(lookup_expr='icontains', label=_("Nom du père"))
    prenoms_pere = filters.CharFilter(lookup_expr='icontains', label=_("Prénoms du père"))
    nom_mere = filters.CharFilter(lookup_expr='icontains', label=_("Nom de la mère"))
    prenoms_mere = filters.CharFilter(lookup_expr='icontains', label=_("Prénoms de la mère"))
    
    # Filtre avancé pour recherche par nom complet enfant
    nom_complet_enfant = filters.CharFilter(method='filter_nom_complet_enfant', label=_("Nom complet de l'enfant"))
    
    def filter_nom_complet_enfant(self, queryset, name, value):
        """Filtre sur le nom complet de l'enfant"""
        terms = value.split()
        q_objects = Q()
        for term in terms:
            q_objects |= (
                Q(prenoms_enfant__icontains=term) | 
                Q(nom_enfant__icontains=term)
            )
        return queryset.filter(q_objects)

    class Meta:
        model = Enregistrement
        fields = {
            'date_delivrance': ['exact', 'year', 'month'],
            'lieu_delivrance': ['exact', 'icontains'],
            'date_enregistrement': ['year'],
        }


class PaiementFilter(filters.FilterSet):
    """Filtres pour le modèle Paiement"""
    reference = filters.CharFilter(lookup_expr='icontains', label=_("Référence"))
    statut = filters.ChoiceFilter(choices=Paiement.StatutPaiement.choices, label=_("Statut"))
    methode = filters.ChoiceFilter(choices=Paiement.MethodePaiement.choices, label=_("Méthode"))
    date_paiement_min = filters.DateTimeFilter(field_name='date_paiement', lookup_expr='gte', label=_("Après le"))
    date_paiement_max = filters.DateTimeFilter(field_name='date_paiement', lookup_expr='lte', label=_("Avant le"))
    montant_min = filters.NumberFilter(field_name='montant', lookup_expr='gte', label=_("Montant min"))
    montant_max = filters.NumberFilter(field_name='montant', lookup_expr='lte', label=_("Montant max"))
    
    # Filtre pour retrouver les paiements par numéro de demande
    numero_demande = filters.CharFilter(field_name='demande__numero_demande', lookup_expr='icontains', label=_("Numéro de demande"))
    
    # Filtre pour retrouver les paiements par utilisateur
    utilisateur = filters.ModelChoiceFilter(
        field_name='demande__utilisateur',
        queryset=Utilisateur.objects.all(),
        label=_("Utilisateur")
    )

    class Meta:
        model = Paiement
        fields = {
            'telephone': ['exact', 'icontains'],
            'id_transaction': ['exact', 'icontains'],
        }


class RejetFilter(filters.FilterSet):
    """Filtres pour le modèle Rejet"""
    agent = filters.ModelChoiceFilter(queryset=Agent.objects.all(), label=_("Agent"))
    date_rejet_min = filters.DateTimeFilter(field_name='date_rejet', lookup_expr='gte', label=_("Après le"))
    date_rejet_max = filters.DateTimeFilter(field_name='date_rejet', lookup_expr='lte', label=_("Avant le"))
    delais_recours_expire = filters.BooleanFilter(method='filter_delais_recours', label=_("Délai de recours expiré"))
    
    # Filtre pour retrouver les rejets par numéro de demande
    numero_demande = filters.CharFilter(field_name='demande__numero_demande', lookup_expr='icontains', label=_("Numéro de demande"))
    
    # Filtre pour rechercher dans le motif
    motif_contient = filters.CharFilter(field_name='motif', lookup_expr='icontains', label=_("Motif contient"))
    
    def filter_delais_recours(self, queryset, name, value):
        """Filtre pour voir si le délai de recours est expiré"""
        now = datetime.now()
        if value:  # Si True, retourne les rejets dont le délai est expiré
            return queryset.filter(delais_recours__lt=now)
        else:  # Si False, retourne les rejets dont le délai n'est pas expiré
            return queryset.filter(delais_recours__gte=now)

    class Meta:
        model = Rejet
        fields = {
            # Champs déjà définis plus haut
        }


class JournalFilter(filters.FilterSet):
    """Filtres pour le modèle Journal"""
    type_action = filters.ChoiceFilter(choices=Journal.TypeAction.choices, label=_("Type d'action"))
    date_action_min = filters.DateTimeFilter(field_name='date_action', lookup_expr='gte', label=_("Après le"))
    date_action_max = filters.DateTimeFilter(field_name='date_action', lookup_expr='lte', label=_("Avant le"))
    utilisateur = filters.ModelChoiceFilter(queryset=Utilisateur.objects.all(), label=_("Utilisateur"))
    
    # Filtre pour les actions concernant une demande spécifique
    demande = filters.ModelChoiceFilter(queryset=Demande.objects.all(), label=_("Demande"))
    numero_demande = filters.CharFilter(field_name='demande__numero_demande', lookup_expr='icontains', label=_("Numéro de demande"))
    
    # Filtre texte sur la description
    description_contient = filters.CharFilter(field_name='description', lookup_expr='icontains', label=_("Description contient"))
    
    # Filtre pour les actions récentes (24h)
    recentes = filters.BooleanFilter(method='filter_recentes', label=_("Actions récentes"))
    
    def filter_recentes(self, queryset, name, value):
        """Filtre pour les actions des dernières 24h"""
        if value:
            date_limite = datetime.now() - timedelta(hours=24)
            return queryset.filter(date_action__gte=date_limite)
        return queryset

    class Meta:
        model = Journal
        fields = {
            'adresse_ip': ['exact'],
        }


class NotificationFilter(filters.FilterSet):
    """Filtres pour le modèle Notification"""
    utilisateur = filters.ModelChoiceFilter(queryset=Utilisateur.objects.all(), label=_("Utilisateur"))
    est_lu = filters.BooleanFilter(label=_("Est lu"))
    type_notification = filters.ChoiceFilter(choices=Notification.TypeNotification.choices, label=_("Type"))
    date_creation_min = filters.DateTimeFilter(field_name='date_creation', lookup_expr='gte', label=_("Après le"))
    date_creation_max = filters.DateTimeFilter(field_name='date_creation', lookup_expr='lte', label=_("Avant le"))
    
    # Filtre pour les notifications récentes (7 jours)
    recentes = filters.BooleanFilter(method='filter_recentes', label=_("Notifications récentes"))
    
    # Filtre texte sur le titre et le message
    texte_contient = filters.CharFilter(method='filter_texte', label=_("Contient"))
    
    def filter_recentes(self, queryset, name, value):
        """Filtre pour les notifications des 7 derniers jours"""
        if value:
            date_limite = datetime.now() - timedelta(days=7)
            return queryset.filter(date_creation__gte=date_limite)
        return queryset
        
    def filter_texte(self, queryset, name, value):
        """Filtre sur le titre et le message"""
        return queryset.filter(
            Q(titre__icontains=value) | 
            Q(message__icontains=value)
        )

    class Meta:
        model = Notification
        fields = {
            'demande': ['exact'],
        }