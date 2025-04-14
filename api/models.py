from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.core.validators import RegexValidator, MinValueValidator
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import uuid


def generate_demande_number():
    return str(uuid.uuid4()).replace('-', '')[:16].upper()


def generate_payment_reference():
    return f"PAY-{str(uuid.uuid4()).replace('-', '')[:10].upper()}"


class UtilisateurManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('L\'email doit être renseigné')
        email = self.normalize_email(email)  # Normalisation de l'email
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(username, email, password, **extra_fields)

    def get_by_natural_key(self, email):
        return self.get(email=email)


    def normalize_email(self, email):
        """Normalise l'adresse email"""
        email = email or ''
        try:
            email_name, domain_part = email.strip().rsplit('@', 1)
        except ValueError:
            pass
        else:
            email = email_name + '@' + domain_part.lower()
        return email.lower()


class Utilisateur(AbstractUser):
    """Modèle utilisateur personnalisé"""

    class RoleChoices(models.TextChoices):
        USER = 'user', _('Utilisateur standard')
        AGENT = 'agent', _('Agent administratif')
        SUPERVISOR = 'supervisor', _('Superviseur')
        ADMIN = 'admin', _('Administrateur système')

    class SexeChoices(models.TextChoices):
        HOMME = 'homme', _('Homme')
        FEMME = 'femme', _('Femme')

    # Champs de base (remplacement des champs existants d'AbstractUser)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)  # <-- Ajoutez cette ligne


    # Champs personnalisés
    sexe = models.CharField(
        max_length=50,
        choices=SexeChoices.choices,
        blank=True,
        null=True
    )
    telephone = models.CharField(
        max_length=20,
        validators=[
            RegexValidator(
                regex=r'^\+?[0-9]{8,15}$',
                message=_("Format: +2250123456789")
            )
        ]
    )
    date_modification = models.DateTimeField(auto_now=True)

    # Nouveau champ role
    role = models.CharField(
        max_length=20,
        choices=RoleChoices.choices,
        default=RoleChoices.USER,
        verbose_name=_("Rôle")
    )

    # Configuration des permissions
    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        related_name="custom_user_set",
        related_query_name="user"
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        related_name="custom_user_set",
        related_query_name="user"
    )

    objects = UtilisateurManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return f"{self.last_name} {self.first_name}"

    @property
    def is_admin(self):
        return self.role == self.RoleChoices.ADMIN
    
    @property
    def is_agent(self):
        return self.role == self.RoleChoices.AGENT
    
    @property
    def is_supervisor(self):
        return self.role == self.RoleChoices.SUPERVISOR



    class Meta:
        verbose_name = _("Utilisateur")
        verbose_name_plural = _("Utilisateurs")
        ordering = ['last_name', 'first_name']

    def save(self, *args, **kwargs):
        """Synchronisation des champs avant sauvegarde"""
        if not self.username:
            self.username = self.email  # Utilisation de l'email comme username si vide
        super().save(*args, **kwargs)






class Agent(Utilisateur):
    """Modèle représentant un agent administratif"""
    class IsActiveItems(models.TextChoices):
        ACTIF = 'actif', _('Actif')
        INACTIF = 'inactif', _('Inactif')

    # Champs spécifiques aux agents
    matricule = models.CharField(max_length=100, unique=True, verbose_name=_("Matricule"))
    photo = models.ImageField(upload_to='agents/photos/', blank=True, null=True)
    commune_service = models.ForeignKey(
        'Commune',
        on_delete=models.CASCADE,
        related_name='agents_service'
    )
    poste = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(
        max_length=20,
        choices=IsActiveItems.choices,
        default=IsActiveItems.ACTIF,
        verbose_name=_("Statut")
    )
   

    class Meta:
        verbose_name = _("Agent")
        verbose_name_plural = _("Agents")

    def __str__(self):
        return f"{self.last_name} {self.first_name} ({self.role})"



class Commune(models.Model):
    """Modèle représentant une commune administrative"""

    class TypeItems(models.TextChoices):
        MAIRIE = 'mairie', _('Mairie')
        SOUS_PREFECTURE = 'sous-prefecture', _('Sous-Préfecture')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name=_("ID"))
    nom = models.CharField(max_length=100, verbose_name=_("Nom"))
    type = models.CharField(
        max_length=50,
        choices=TypeItems.choices,
        blank=True,
        verbose_name=_("Type de commune")
    )
    region = models.CharField(max_length=100, verbose_name=_("Région"))
    adresse_postale = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        verbose_name=_("Adresse postale")
    )
    signature = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        verbose_name=_("Signature officielle")
    )
    telephone = models.CharField(
        max_length=20,
        verbose_name=_("Téléphone"),
        validators=[
            RegexValidator(
                regex=r'^\+?[0-9]{8,15}$',
                message=_("Le numéro de téléphone doit être au format international (ex: +2250123456789).")
            )
        ]
    )
    email = models.EmailField(unique=True, verbose_name=_("Adresse email"))
    date_creation = models.DateTimeField(auto_now_add=True, verbose_name=_("Date de création"))
    date_modification = models.DateTimeField(auto_now=True, verbose_name=_("Dernière modification"))

    def __str__(self):
        return f"{self.nom} ({self.type})"

    class Meta:
        verbose_name = _("Commune")
        verbose_name_plural = _("Communes")
        ordering = ['region', 'nom']
        constraints = [
            models.UniqueConstraint(fields=['nom', 'region'], name='commune_unique')
        ]




class Demande(models.Model):
    """Modèle représentant une demande d'extrait de naissance"""

    class StatutDemande(models.TextChoices):
        EN_ATTENTE = 'en_attente', _('En attente')
        EN_COURS = 'en_cours', _('En cours')
        REJETE = 'rejete', _('Rejeté')
        ECHEC = 'echec', _('Échec')
        SUCCES = 'succes', _('Succès')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name=_("ID"))
    numero_demande = models.CharField(
        max_length=50,
        unique=True,
        verbose_name=_("Numéro de demande"),
        default=generate_demande_number
    )
    utilisateur = models.ForeignKey(
        'Utilisateur',
        on_delete=models.CASCADE,
        related_name='demandes',
        verbose_name=_("Utilisateur demandeur")
    )
    numero_acte = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name=_("Numéro d'acte")
    )
    date_etablissement = models.DateField(verbose_name=_("Date d'établissement"))

    quantite = models.IntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        verbose_name=_("Quantité")
    )

    commune_source = models.ForeignKey(
        'Commune',
        on_delete=models.CASCADE,
        related_name='demandes_source',
        verbose_name=_("Commune source")
    )

    commune_cible = models.ForeignKey(
        'Commune',
        on_delete=models.CASCADE,
        related_name='demandes_cible',
        verbose_name=_("Commune cible")
    )

    statut = models.CharField(
        max_length=20,
        choices=StatutDemande.choices,
        default=StatutDemande.EN_ATTENTE,
        verbose_name=_("Statut de la demande")
    )
    agent_en_charge = models.ForeignKey(
        'Agent',
        on_delete=models.SET_NULL,
        related_name='demandes_en_charge',
        null=True,
        blank=True,
        verbose_name=_("Agent en charge")
    )
    commentaires = models.TextField(
        blank=True,
        null=True,
        verbose_name=_("Commentaires")
    )
    date_demande = models.DateTimeField(auto_now_add=True, verbose_name=_("Date d'envoi de la demande"))
    date_modification = models.DateTimeField(auto_now=True, verbose_name=_("Dernière modification"))

    def __str__(self):
        return f"Demande {self.numero_demande} - {self.utilisateur.last_name} ({self.statut})"

    class Meta:
        verbose_name = _("Demande")
        verbose_name_plural = _("Demandes")
        ordering = ['-date_demande']
        indexes = [
            models.Index(fields=['utilisateur']),
            models.Index(fields=['statut']),
            models.Index(fields=['date_demande']),
        ]


class Enregistrement(models.Model):
    """Modèle représentant un enregistrement d'extrait de naissance"""

    class SexeChoices(models.TextChoices):
        MASCULIN = 'masculin', _('Masculin')
        FEMININ = 'feminin', _('Feminin')

    # Identifiants
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name=_("ID"))
    agent = models.ForeignKey(
        'Agent',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='enregistrements',
        verbose_name=_("Agent traitant")
    )

    # Informations sur l'enregistrement
    numero_acte = models.CharField(max_length=50, verbose_name=_("Numéro d'acte"))
    date_acte = models.DateField(verbose_name=_("Année de l'acte"))
    date_enregistrement = models.DateField(verbose_name=_("Année de l'enregistrement"))

    # Informations sur l'enfant
    nom_enfant = models.CharField(max_length=100, verbose_name=_("Nom de l'enfant"))
    prenoms_enfant = models.CharField(max_length=200, verbose_name=_("Prénom(s) de l'enfant"))
    date_naissance = models.DateField(verbose_name=_("Date de naissance"))
    heure_naissance = models.TimeField(verbose_name=_("Heure de naissance"), null=True, blank=True)
    lieu_naissance = models.CharField(max_length=200, verbose_name=_("Lieu de naissance"))
    sexe = models.CharField(
        max_length=50,
        choices=SexeChoices.choices,
        blank=True,
        null=True
    )

    # Informations sur le père
    nom_pere = models.CharField(max_length=100, verbose_name=_("Nom du père"))
    prenoms_pere = models.CharField(max_length=200, verbose_name=_("Prénom(s) du père"))
    nationalite_pere = models.CharField(max_length=100, verbose_name=_("Nationalité du père"))
    profession_pere = models.CharField(max_length=100, verbose_name=_("Profession du père"))
    domicile_pere = models.CharField(max_length=200, verbose_name=_("Domicile du père"))

    # Informations sur la mère
    nom_mere = models.CharField(max_length=100, verbose_name=_("Nom de la mère"))
    prenoms_mere = models.CharField(max_length=200, verbose_name=_("Prénom(s) de la mère"))
    nationalite_mere = models.CharField(max_length=100, verbose_name=_("Nationalité de la mère"))
    profession_mere = models.CharField(max_length=100, verbose_name=_("Profession de la mère"))
    domicile_mere = models.CharField(max_length=200, verbose_name=_("Domicile de la mère"))

    # Mentions marginales
    mentions_marginales = models.TextField(verbose_name=_("Mentions marginales"), null=True, blank=True)

    # Informations administratives
    date_delivrance = models.DateField(verbose_name=_("Date de délivrance"))
    lieu_delivrance = models.CharField(max_length=200, verbose_name=_("Lieu de délivrance"))
    nom_officier_etat_civil = models.CharField(max_length=200, verbose_name=_("Nom de l'officier d'état civil"))
    signature_officier = models.CharField(max_length=200, verbose_name=_("Signature de l'officier"), null=True,
                                          blank=True)
    fonction_officier = models.CharField(max_length=200, verbose_name=_("Fonction de l'officier"), null=True,
                                         blank=True)
    sceau_officiel = models.CharField(max_length=200, verbose_name=_("Sceau officiel"), null=True, blank=True)

    # Suivi des modifications
    date_creation = models.DateTimeField(auto_now_add=True, verbose_name=_("Date de création"))
    date_modification = models.DateTimeField(auto_now=True, verbose_name=_("Dernière modification"))

    def __str__(self):
        return f"{self.nom_enfant} {self.prenoms_enfant} - {self.date_naissance}"

    class Meta:
        verbose_name = _("Enregistrement")
        verbose_name_plural = _("Enregistrements")
        ordering = ['-date_enregistrement']
        indexes = [
            models.Index(fields=['numero_acte']),
            models.Index(fields=['nom_enfant', 'prenoms_enfant']),
            models.Index(fields=['date_naissance']),
        ]
        constraints = [
            models.UniqueConstraint(fields=['numero_acte', 'date_acte'], name='acte_unique')
        ]


class Paiement(models.Model):
    """Modèle représentant un paiement pour une demande"""

    class StatutPaiement(models.TextChoices):
        EN_ATTENTE = 'en_attente', _('En attente')
        PAYE = 'paye', _('Payé')
        ANNULE = 'annule', _('Annulé')
        REMBOURSE = 'rembourse', _('Remboursé')

    class MethodePaiement(models.TextChoices):
        TRESOR_MONEY = 'tresor_money', _('Tresor money')
        MTN_MONEY = 'mtn_money', _('MTN Money')
        ORANGE_MONEY = 'orange_money', _('Orange Money')
        MOOV_MONEY = 'moov_money', _('Moov Money')
        WAVE = 'wave', _('Wave')

    id = models.AutoField(primary_key=True, verbose_name=_("ID"))
    reference = models.CharField(
        max_length=50,
        unique=True,
        default=generate_payment_reference,
        verbose_name=_("Référence de paiement")
    )
    demande = models.OneToOneField(
        'Demande',
        on_delete=models.CASCADE,
        related_name='paiement',
        verbose_name=_("Demande associée")
    )
    montant = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name=_("Montant")
    )
    methode = models.CharField(
        max_length=50,
        choices=MethodePaiement.choices,
        verbose_name=_("Méthode de paiement")
    )
    telephone = models.CharField(
        max_length=20,
        verbose_name=_("Téléphone"),
        validators=[
            RegexValidator(
                regex=r'^\+?[0-9]{8,15}$',
                message=_("Le numéro de téléphone doit être au format international (ex: +2250123456789).")
            )
        ]
    )
    id_transaction = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        verbose_name=_("ID de transaction")
    )
    statut = models.CharField(
        max_length=20,
        choices=StatutPaiement.choices,
        default=StatutPaiement.EN_ATTENTE,
        verbose_name=_("Statut du paiement")
    )
    date_paiement = models.DateTimeField(auto_now_add=True, verbose_name=_("Date initiale du paiement"))

    def __str__(self):
        return f"Paiement {self.reference} - {self.montant} ({self.statut})"

    def confirmer_paiement(self, id_transaction=None):
        """Confirme un paiement et met à jour son statut"""
        self.statut = self.StatutPaiement.PAYE
        if id_transaction:
            self.id_transaction = id_transaction
        self.date_confirmation = timezone.now()
        self.save()

    class Meta:
        verbose_name = _("Paiement")
        verbose_name_plural = _("Paiements")
        ordering = ['-date_paiement']
        indexes = [
            models.Index(fields=['statut']),
            models.Index(fields=['date_paiement']),
        ]


def get_default_delais_recours():
    """Returns default delais_recours value"""
    return timezone.now() + timedelta(days=30)


class Rejet(models.Model):
    """Modèle représentant un rejet de demande"""

    id = models.AutoField(primary_key=True, verbose_name=_("ID"))
    motif = models.TextField(verbose_name=_("Motif du rejet"))
    demande = models.OneToOneField(
        'Demande',
        on_delete=models.CASCADE,
        related_name='rejet',
        verbose_name=_("Demande rejetée")
    )
    agent = models.ForeignKey(
        'Agent',
        on_delete=models.CASCADE,
        related_name='rejets',
        verbose_name=_("Agent ayant rejeté")
    )
    procedure_recours = models.TextField(
        blank=True,
        null=True,
        verbose_name=_("Procédure de recours")
    )
    date_rejet = models.DateTimeField(auto_now_add=True, verbose_name=_("Date du rejet"))
    delais_recours = models.DateTimeField(verbose_name=_("Délai de recours"),
                                          default=get_default_delais_recours)

    def __str__(self):
        return f"Rejet de la demande {self.demande.numero_demande} par {self.agent.last_name}"

    def save(self, *args, **kwargs):
        """Met à jour le statut de la demande lors du rejet"""
        self.demande.statut = Demande.StatutDemande.REJETE
        self.demande.save()
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = _("Rejet")
        verbose_name_plural = _("Rejets")
        ordering = ['-date_rejet']


class Journal(models.Model):
    """Modèle pour tracer toutes les actions importantes du système"""

    class TypeAction(models.TextChoices):
        CREATION = 'creation', _('Création')
        MODIFICATION = 'modification', _('Modification')
        SUPPRESSION = 'suppression', _('Suppression')
        CONSULTATION = 'consultation', _('Consultation')
        VALIDATION = 'validation', _('Validation')
        REJET = 'rejet', _('Rejet')
        PAIEMENT = 'paiement', _('Paiement')
        CONNEXION = 'connexion', _('Connexion')
        DECONNEXION = 'deconnexion', _('Déconnexion')

    id = models.AutoField(primary_key=True, verbose_name=_("ID"))
    date_action = models.DateTimeField(auto_now_add=True, verbose_name=_("Date de l'action"))
    type_action = models.CharField(
        max_length=50,
        choices=TypeAction.choices,
        verbose_name=_("Type d'action")
    )
    description = models.TextField(verbose_name=_("Description"))

    # Utilisateur ou agent qui a effectué l'action
    utilisateur = models.ForeignKey(
        Utilisateur, 
        on_delete=models.CASCADE,
        related_name='journals_utilisateur',
        related_query_name='journal_utilisateur',
        null=True,
        blank=True
    )
    

    # Objet concerné par l'action
    demande = models.ForeignKey(
        'Demande',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='journal',
        verbose_name=_("Demande concernée")
    )

    # Informations techniques
    adresse_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_("Adresse IP")
    )

    def __str__(self):
        # Get the actor - either utilisateur or None
        acteur = self.utilisateur
        
        # Format the actor string
        acteur_str = str(acteur) if acteur else "Système"
        
        return f"{self.date_action} - {self.type_action} par {acteur_str}"


    class Meta:
        verbose_name = _("Journal")
        verbose_name_plural = _("Journal des actions")
        ordering = ['-date_action']
        indexes = [
            models.Index(fields=['date_action']),
            models.Index(fields=['type_action']),
        ]


class Notification(models.Model):
    """Modèle pour les notifications envoyées aux utilisateurs"""
    class TypeNotification(models.TextChoices):
        INFO = 'info', _('Information')
        SUCCES = 'succes', _('Succès')
        ERREUR = 'erreur', _('Erreur')

    id = models.AutoField(primary_key=True, verbose_name=_("ID"))
    titre = models.CharField(max_length=200, verbose_name=_("Titre"))
    message = models.TextField(verbose_name=_("Message"))
    type_notification = models.CharField(
        max_length=50,
        choices=TypeNotification.choices,
        default=TypeNotification.INFO,
        verbose_name=_("Type de notification")
    )
    date_creation = models.DateTimeField(auto_now_add=True, verbose_name=_("Date de création"))
    est_lu = models.BooleanField(default=False, verbose_name=_("Est lu"))
    date_lecture = models.DateTimeField(null=True, blank=True, verbose_name=_("Date de lecture"))

    # Destinataire (peut être un Utilisateur ou un Agent via l'héritage)
    utilisateur = models.ForeignKey(
        Utilisateur,
        on_delete=models.CASCADE,
        related_name='notifications',
        verbose_name=_("Destinataire")
    )

    # Objet concerné (optionnel)
    demande = models.ForeignKey(
        'Demande',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications',
        verbose_name=_("Demande concernée")
    )

    def marquer_comme_lu(self):
        """Marque la notification comme lue"""
        self.est_lu = True
        self.date_lecture = timezone.now()
        self.save()

    def __str__(self):
        return f"{self.titre} - {self.utilisateur} ({self.date_creation})"

    class Meta:
        verbose_name = _("Notification")
        verbose_name_plural = _("Notifications")
        ordering = ['-date_creation']
        indexes = [
            models.Index(fields=['est_lu']),
            models.Index(fields=['date_creation']),
        ]
