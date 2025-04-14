from rest_framework import permissions
from django.utils.translation import gettext_lazy as _
from django.db.models import Q
from .models import Demande, Commune, Agent, Utilisateur, Notification, Enregistrement, Journal, Paiement, Rejet


class BasePermission(permissions.BasePermission):
    """Classe de base pour toutes les permissions"""
    message = _("Vous n'avez pas les autorisations nécessaires.")


class IsAuthenticated(BasePermission):
    """Permission de base vérifiant que l'utilisateur est authentifié"""
    message = _("Vous devez être connecté pour accéder à cette ressource.")

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsAdmin(BasePermission):
    """Vérifie que l'utilisateur est un administrateur"""
    message = _("Cette action est réservée aux administrateurs.")

    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role == Utilisateur.RoleChoices.ADMIN)


class IsAgent(BasePermission):
    """Vérifie que l'utilisateur est un agent"""
    message = _("Cette action est réservée aux agents.")

    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role == Utilisateur.RoleChoices.AGENT)


class IsSupervisor(BasePermission):
    """Vérifie que l'utilisateur est un superviseur"""
    message = _("Cette action est réservée aux superviseurs.")

    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role == Utilisateur.RoleChoices.SUPERVISOR)


class IsStandardUser(BasePermission):
    """Vérifie que l'utilisateur est un utilisateur standard"""
    message = _("Cette action est réservée aux utilisateurs standard.")

    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role == Utilisateur.RoleChoices.USER)


class IsAdminOrSupervisor(BasePermission):
    """Vérifie que l'utilisateur est un administrateur ou un superviseur"""
    message = _("Cette action est réservée aux administrateurs et superviseurs.")

    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role in [Utilisateur.RoleChoices.ADMIN, 
                                     Utilisateur.RoleChoices.SUPERVISOR])


# ========== PERMISSIONS LIÉES AUX DEMANDES ==========

class CanCreateDemande(BasePermission):
    """Autorise la création de demandes pour les utilisateurs standard seulement"""
    message = _("Seuls les utilisateurs standard peuvent créer une demande.")

    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role == Utilisateur.RoleChoices.USER)


class CanUpdateOwnDemande(BasePermission):
    """Autorise la modification d'une demande par son créateur si elle est rejetée"""
    message = _("Vous ne pouvez modifier que vos propres demandes rejetées.")
    
    def has_object_permission(self, request, view, obj):
        # Vérifier que l'utilisateur est le créateur et que la demande est rejetée
        if not isinstance(obj, Demande):
            return False
        
        return (obj.utilisateur == request.user and 
                obj.statut == Demande.StatutDemande.REJETE)


class CanViewOwnDemandes(BasePermission):
    """Autorise un utilisateur à consulter ses propres demandes"""
    message = _("Vous ne pouvez consulter que vos propres demandes.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Demande):
            return False
        return obj.utilisateur == request.user

    def has_permission(self, request, view):
        # Pour les listes de demandes
        return request.user.is_authenticated


class CanProcessDemande(BasePermission):
    """Autorise les agents à traiter les demandes de leur commune source"""
    message = _("Vous ne pouvez traiter que les demandes assignées à votre commune.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Demande) or not isinstance(request.user, Agent):
            return False
        
        return (request.user.commune_service == obj.commune_source and
                obj.statut in [Demande.StatutDemande.EN_ATTENTE, Demande.StatutDemande.EN_COURS])


class CanViewCommuneDemandes(BasePermission):
    """Autorise les agents et superviseurs à consulter les demandes de leur commune"""
    message = _("Vous ne pouvez consulter que les demandes concernant votre commune.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Demande) or not hasattr(request.user, 'commune_service'):
            return False
        
        return (request.user.commune_service == obj.commune_source or 
                request.user.commune_service == obj.commune_cible)

    def has_permission(self, request, view):
        # Pour les listes de demandes
        return (request.user.is_authenticated and 
                request.user.role in [Utilisateur.RoleChoices.AGENT, 
                                     Utilisateur.RoleChoices.SUPERVISOR, 
                                     Utilisateur.RoleChoices.ADMIN])


class CanDestinationCommuneApprove(BasePermission):
    """Autorise la commune de destination à approuver une demande déjà traitée"""
    message = _("La commune de destination ne peut approuver qu'après traitement par la commune source.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Demande) or not isinstance(request.user, Agent):
            return False
        
        return (request.user.commune_service == obj.commune_cible and 
                obj.statut != Demande.StatutDemande.EN_ATTENTE)


class CanRejectDemande(BasePermission):
    """Autorise les agents à rejeter une demande de leur commune source"""
    message = _("Vous ne pouvez pas rejeter cette demande.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Demande) or not isinstance(request.user, Agent):
            return False
        
        return (request.user.commune_service == obj.commune_source and
                obj.statut in [Demande.StatutDemande.EN_ATTENTE, Demande.StatutDemande.EN_COURS])


class CanAssignDemande(BasePermission):
    """Autorise les superviseurs à assigner des demandes aux agents"""
    message = _("Vous ne pouvez pas assigner cette demande.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Demande) or not isinstance(request.user, Agent):
            return False
        
        return (request.user.role == Utilisateur.RoleChoices.SUPERVISOR and
                request.user.commune_service == obj.commune_source)


# ========== PERMISSIONS LIÉES AUX NOTIFICATIONS ==========

class CanViewOwnNotifications(BasePermission):
    """Autorise un utilisateur à consulter ses propres notifications"""
    message = _("Vous ne pouvez consulter que vos propres notifications.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Notification):
            return False
        return obj.utilisateur == request.user

    def has_permission(self, request, view):
        # Pour les listes de notifications
        return request.user.is_authenticated


class CanSendNotification(BasePermission):
    """Autorise les agents, superviseurs et admins à envoyer des notifications"""
    message = _("Vous n'êtes pas autorisé à envoyer des notifications.")
    
    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role in [Utilisateur.RoleChoices.AGENT,
                                     Utilisateur.RoleChoices.SUPERVISOR,
                                     Utilisateur.RoleChoices.ADMIN])


class CanViewCommuneNotifications(BasePermission):
    """Autorise les agents et superviseurs à voir les notifications liées à leur commune"""
    message = _("Vous ne pouvez consulter que les notifications liées à votre commune.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Notification) or not hasattr(request.user, 'commune_service'):
            return False
        
        # Si notification liée à une demande, vérifier que la demande concerne la commune
        if obj.demande:
            return (request.user.commune_service == obj.demande.commune_source or 
                    request.user.commune_service == obj.demande.commune_cible)
        
        # Sinon, vérifier que le destinataire est de la même commune
        if isinstance(obj.utilisateur, Agent):
            return request.user.commune_service == obj.utilisateur.commune_service
        
        return False


class CanMarkNotificationAsRead(BasePermission):
    """Autorise un utilisateur à marquer ses propres notifications comme lues"""
    message = _("Vous ne pouvez marquer comme lues que vos propres notifications.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Notification):
            return False
        return obj.utilisateur == request.user


# ========== PERMISSIONS LIÉES AUX ENREGISTREMENTS ==========

class CanCreateUpdateEnregistrement(BasePermission):
    """Seuls les superviseurs peuvent créer et modifier des enregistrements"""
    message = _("Seuls les superviseurs peuvent gérer les enregistrements.")
    
    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.role == Utilisateur.RoleChoices.SUPERVISOR)
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Enregistrement) or not isinstance(request.user, Agent):
            return False
        
        # Vérifier si l'enregistrement est lié à la commune du superviseur
        if obj.agent:
            return request.user.commune_service == obj.agent.commune_service
        
        return False


class CanViewEnregistrement(BasePermission):
    """Autorise la consultation des enregistrements"""
    message = _("Vous n'êtes pas autorisé à consulter cet enregistrement.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Enregistrement):
            return False
        
        # Administrateur peut tout voir
        if request.user.role == Utilisateur.RoleChoices.ADMIN:
            return True
            
        # Superviseur et agent peuvent voir les enregistrements de leur commune
        if isinstance(request.user, Agent) and obj.agent:
            return request.user.commune_service == obj.agent.commune_service
            
        # Utilisateur standard ne peut pas voir les enregistrements
        return False


# ========== PERMISSIONS LIÉES AU JOURNAL ==========

class CanViewCommuneJournal(BasePermission):
    """Permet aux superviseurs de voir les actions des agents de leur commune"""
    message = _("Vous ne pouvez consulter que les journaux liés à votre commune.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Journal) or not isinstance(request.user, Agent):
            return False
            
        if request.user.role != Utilisateur.RoleChoices.SUPERVISOR and request.user.role != Utilisateur.RoleChoices.ADMIN:
            return False
        
        # Si l'action concerne un utilisateur (agent) de la même commune
        if obj.utilisateur and isinstance(obj.utilisateur, Agent):
            return request.user.commune_service == obj.utilisateur.commune_service
        
        # Si l'action concerne une demande liée à la commune
        if obj.demande:
            return (request.user.commune_service == obj.demande.commune_source or 
                    request.user.commune_service == obj.demande.commune_cible)
        
        # Admin voit tout
        return request.user.role == Utilisateur.RoleChoices.ADMIN

    def has_permission(self, request, view):
        return (request.user.is_authenticated and
                (request.user.role == Utilisateur.RoleChoices.SUPERVISOR or 
                 request.user.role == Utilisateur.RoleChoices.ADMIN))


# ========== PERMISSIONS LIÉES AUX UTILISATEURS ==========

class CanUpdateOwnProfile(BasePermission):
    """Autorise un utilisateur à mettre à jour son propre profil"""
    message = _("Vous ne pouvez modifier que votre propre profil.")
    
    def has_object_permission(self, request, view, obj):
        return obj == request.user


class CanManageCommuneAgents(BasePermission):
    """Permet aux superviseurs de gérer les agents de leur commune"""
    message = _("Vous ne pouvez gérer que les agents de votre commune.")
    
    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                (request.user.role == Utilisateur.RoleChoices.SUPERVISOR or
                 request.user.role == Utilisateur.RoleChoices.ADMIN))
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Agent):
            return False
            
        # Admin peut gérer tous les agents
        if request.user.role == Utilisateur.RoleChoices.ADMIN:
            return True
            
        # Superviseur peut gérer les agents de sa commune
        if isinstance(request.user, Agent) and request.user.role == Utilisateur.RoleChoices.SUPERVISOR:
            return request.user.commune_service == obj.commune_service
            
        return False


class CanViewAllAgents(BasePermission):
    """Permet à l'administrateur de voir tous les agents"""
    message = _("Seuls les administrateurs peuvent voir tous les agents.")
    
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == Utilisateur.RoleChoices.ADMIN


class CanViewAgentProfile(BasePermission):
    """Détermine qui peut voir le profil complet d'un agent"""
    message = _("Vous n'êtes pas autorisé à voir le profil complet de cet agent.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Agent):
            return False
        
        # Admin et superviseur de la même commune peuvent voir
        if request.user.role == Utilisateur.RoleChoices.ADMIN:
            return True
            
        if isinstance(request.user, Agent) and request.user.role == Utilisateur.RoleChoices.SUPERVISOR:
            return request.user.commune_service == obj.commune_service
            
        # Agent peut voir son propre profil
        if request.user == obj:
            return True
            
        return False


class CanViewBasicAgentInfo(BasePermission):
    """Permet de voir les informations de base d'un agent"""
    message = _("Vous n'êtes pas autorisé à voir les informations de cet agent.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Agent):
            return False
        
        # Info publique pour les agents liés aux demandes
        if isinstance(request.user, Agent):
            # Vérifier s'il existe une demande qui concerne les deux communes
            return Demande.objects.filter(
                Q(commune_source=request.user.commune_service, commune_cible=obj.commune_service) | 
                Q(commune_source=obj.commune_service, commune_cible=request.user.commune_service)
            ).exists()
            
        # Utilisateur standard ne peut voir que les infos de base des agents traitant ses demandes
        demandes_liees = Demande.objects.filter(
            utilisateur=request.user,
            agent_en_charge=obj
        ).exists()
        
        return demandes_liees


# ========== PERMISSIONS LIÉES AUX COMMUNES ==========

class CanViewCommunes(BasePermission):
    """Tous les utilisateurs authentifiés peuvent voir les communes"""
    message = _("Vous devez être connecté pour consulter les communes.")
    
    def has_permission(self, request, view):
        return request.user.is_authenticated


class CanManageCommunes(BasePermission):
    """Seul l'administrateur peut gérer les communes"""
    message = _("Seuls les administrateurs peuvent gérer les communes.")
    
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == Utilisateur.RoleChoices.ADMIN


# ========== PERMISSIONS LIÉES AUX STATISTIQUES ==========

class CanViewCommuneStats(BasePermission):
    """Permet aux superviseurs de voir les statistiques de leur commune"""
    message = _("Vous ne pouvez consulter que les statistiques de votre commune.")
    
    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                (request.user.role == Utilisateur.RoleChoices.SUPERVISOR or
                 request.user.role == Utilisateur.RoleChoices.ADMIN))
                 
    def has_object_permission(self, request, view, obj):
        # Admin voit toutes les stats
        if request.user.role == Utilisateur.RoleChoices.ADMIN:
            return True
            
        # Superviseur voit uniquement les stats de sa commune
        if isinstance(request.user, Agent) and request.user.role == Utilisateur.RoleChoices.SUPERVISOR:
            if isinstance(obj, Commune):
                return request.user.commune_service == obj
            elif hasattr(obj, 'commune_service'):
                return request.user.commune_service == obj.commune_service
            elif hasattr(obj, 'commune_source'):
                return (request.user.commune_service == obj.commune_source or
                        request.user.commune_service == obj.commune_cible)
                
        return False


class CanViewOwnStats(BasePermission):
    """Permet aux utilisateurs standard de voir leurs propres statistiques"""
    message = _("Vous ne pouvez consulter que vos propres statistiques.")
    
    def has_permission(self, request, view):
        return request.user.is_authenticated
        
    def has_object_permission(self, request, view, obj):
        # Vérifier si les stats concernent l'utilisateur
        if hasattr(obj, 'utilisateur'):
            return obj.utilisateur == request.user
        return False


# ========== PERMISSIONS LIÉES AUX PAIEMENTS ==========

class CanManageOwnPayments(BasePermission):
    """Autorise un utilisateur à gérer ses propres paiements"""
    message = _("Vous ne pouvez gérer que vos propres paiements.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Paiement):
            return False
        return obj.demande.utilisateur == request.user


class CanViewCommunePayments(BasePermission):
    """Autorise les agents et superviseurs à voir les paiements liés à leur commune"""
    message = _("Vous ne pouvez consulter que les paiements liés à votre commune.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Paiement) or not isinstance(request.user, Agent):
            return False
        
        return (request.user.commune_service == obj.demande.commune_source or 
                request.user.commune_service == obj.demande.commune_cible)


# ========== PERMISSIONS LIÉES AUX CONTACTS ==========

class CanContactRelatedAgents(BasePermission):
    """Permet aux agents de contacter les agents des communes liées à une demande"""
    message = _("Vous ne pouvez contacter que les agents liés à une demande que vous traitez.")
    
    def has_object_permission(self, request, view, obj):
        if not isinstance(request.user, Agent) or not isinstance(obj, Agent):
            return False
        
        # Si l'agent est soi-même, pas besoin de permission
        if obj == request.user:
            return True
            
        # Vérifier s'il existe une demande qui concerne les deux communes
        commune_agent = obj.commune_service
        commune_current = request.user.commune_service
        
        # Rechercher une demande qui relie les deux communes
        demandes_liees = Demande.objects.filter(
            Q(commune_source=commune_current, commune_cible=commune_agent) | 
            Q(commune_source=commune_agent, commune_cible=commune_current)
        ).exists()
        
        return demandes_liees

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == Utilisateur.RoleChoices.AGENT


# ========== PERMISSIONS COMPOSITES ==========

class IsAdminOrIsOwner(BasePermission):
    """L'utilisateur est soit administrateur, soit propriétaire de la ressource"""
    message = _("Vous n'avez pas les droits pour accéder à cette ressource.")
    
    def has_object_permission(self, request, view, obj):
        # Admin peut tout faire
        if request.user.role == Utilisateur.RoleChoices.ADMIN:
            return True
            
        # Vérifier si l'utilisateur est propriétaire
        if hasattr(obj, 'utilisateur'):
            return obj.utilisateur == request.user
        
        return obj == request.user


class ReadOnly(BasePermission):
    """Permission en lecture seule"""
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS


class ReadOnlyForAgents(BasePermission):
    """Lecture seule pour les agents, mais pas pour superviseurs ou admins"""
    message = _("Les agents ne peuvent qu'accéder en lecture.")
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
            
        if request.user.role == Utilisateur.RoleChoices.AGENT:
            return request.method in permissions.SAFE_METHODS
            
        return request.user.role in [Utilisateur.RoleChoices.SUPERVISOR, Utilisateur.RoleChoices.ADMIN]