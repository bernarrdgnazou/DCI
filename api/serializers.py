from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from .models import (
    Utilisateur, Commune, Agent, Demande, Enregistrement,
    Paiement, Rejet, Journal, Notification
)
from django.core.validators import validate_email
from django.core.exceptions import ValidationError



class UtilisateurSerializer(serializers.ModelSerializer):
    """Serializer for the Utilisateur model"""
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    password_confirmation = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = Utilisateur
        fields = [
            'id', 'email', 'role', 'last_name', 'first_name', 'sexe', 'telephone',
            'password', 'password_confirmation', 'date_joined',
            'date_modification', 'is_active'
        ]
        read_only_fields = ['id', 'date_creation', 'date_modification']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        """Validate that passwords match"""
        if attrs.get('password') != attrs.get('password_confirmation'):
            raise serializers.ValidationError(
                {"password_confirmation": _("Passwords do not match.")}
            )
        return attrs

    def create(self, validated_data):
        """Create user with hashed password"""
        validated_data.pop('password_confirmation')
        user = Utilisateur.objects.create_user(
            email=validated_data['email'],
            nom=validated_data['last_name'],
            prenoms=validated_data['first_name'],
            password=validated_data['password']
        )

        # Add optional fields if present
        if 'sexe' in validated_data:
            user.sexe = validated_data['sexe']
        if 'telephone' in validated_data:
            user.telephone = validated_data['telephone']

        user.save()
        return user

    def update(self, instance, validated_data):
        """Update user with password protection"""
        if 'password' in validated_data:
            password = validated_data.pop('password')
            validated_data.pop('password_confirmation', None)
            instance.set_password(password)

        return super().update(instance, validated_data)

    def validate_email(self, value):
        if Utilisateur.objects.exclude(pk=self.instance.pk if self.instance else None).filter(email=value).exists():
            raise serializers.ValidationError("Un utilisateur avec cet email existe déjà.")
        return value


    def validate_telephone(self, value):
        if not value.startswith('+') or not value[1:].isdigit():
            raise serializers.ValidationError("Le numéro doit être au format international (+XXX).")
        return value

    def validate_password(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Le mot de passe doit contenir au moins 10 caractères.")
        if not any(c.isupper() for c in value):
            raise serializers.ValidationError("Le mot de passe doit contenir une majuscule.")
        return value


class UtilisateurListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for user lists"""

    class Meta:
        model = Utilisateur
        fields = ['id', 'email', 'last_name', 'fisrt_name', 'is_active']


class UtilisateurUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user information without password"""

    class Meta:
        model = Utilisateur
        fields = ['last_name', 'first_name', 'sexe', 'telephone']


class CommuneSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for Commune model"""

    class Meta:
        model = Commune
        fields = [
            'id', 'nom', 'type', 'region', 'adresse_postale',
            'signature', 'telephone', 'email', 'date_creation',
            'date_modification'
        ]
        read_only_fields = ['id', 'date_creation', 'date_modification']


class CommuneListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for commune lists"""

    class Meta:
        model = Commune
        fields = ['id', 'nom', 'type', 'region']


class AgentSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for Agent model"""
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    password_confirmation = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    commune_service_details = CommuneSerializer(source='commune_service', read_only=True)

    class Meta:
        model = Agent
        fields = [
            'id', 'username', 'email', 'last_name', 'first_name', 'matricule',
            'photo', 'telephone', 'commune_service', 'commune_service_details',
            'poste', 'role', 'password', 'password_confirmation',
            'date_creation', 'date_modification', 'is_active'
        ]
        read_only_fields = ['id', 'date_creation', 'date_modification']

    def validate(self, attrs):
        """Validate that passwords match"""
        if attrs.get('password') != attrs.get('password_confirmation'):
            raise serializers.ValidationError(
                {"password_confirmation": _("Passwords do not match.")}
            )
        return attrs

    def create(self, validated_data):
        """Create agent with hashed password"""
        validated_data.pop('password_confirmation')
        password = validated_data.pop('password')

        agent = Agent(**validated_data)
        agent.set_password(password)
        agent.save()

        return agent

    def update(self, instance, validated_data):
        """Update agent with password protection"""
        if 'password' in validated_data:
            password = validated_data.pop('password')
            validated_data.pop('password_confirmation', None)
            instance.set_password(password)

        return super().update(instance, validated_data)


    def validate_password(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Le mot de passe doit contenir au moins 10 caractères.")
        if not any(c.isupper() for c in value):
            raise serializers.ValidationError("Le mot de passe doit contenir une majuscule.")
        return value


class AgentListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for agent lists"""
    commune_nom = serializers.CharField(source='commune_service.nom', read_only=True)
    is_active = serializers.SerializerMethodField()


    class Meta:
        model = Agent
        fields = ['id', 'username', 'last_name', 'first_name', 'role', 'commune_nom', 'is_active']

    def get_is_active(self, obj):
        if obj.is_active:
            return obj.is_active == "actif"
        return None



class AgentUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating agent information without password"""

    class Meta:
        model = Agent
        fields = ['last_name', 'first_name', 'telephone', 'photo', 'poste', 'commune_service']




class DemandeSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for Demande model"""
    utilisateur_details = UtilisateurListSerializer(source='utilisateur', read_only=True)
    commune_source_details = CommuneListSerializer(source='commune_source', read_only=True)
    commune_cible_details = CommuneListSerializer(source='commune_cible', read_only=True)
    agent_en_charge_details = AgentListSerializer(source='agent_en_charge', read_only=True, required=False)
    a_paiement = serializers.SerializerMethodField()


    class Meta:
        model = Demande
        fields = [
            'id', 'numero_demande', 'utilisateur', 'utilisateur_details',
            'numero_acte', 'date_etablissement', 'quantite',
            'commune_source', 'commune_source_details',
            'commune_cible', 'commune_cible_details',
            'statut', 'agent_en_charge', 'agent_en_charge_details',
            'commentaires', 'date_demande', 'date_modification',
            'a_paiement'
        ]
        read_only_fields = [
            'id', 'numero_demande', 'date_demande', 'date_modification',
            'agent_en_charge', 'statut'
        ]

    def get_a_paiement(self, obj):
        """Check if a request has an associated payment"""
        try:
            return hasattr(obj, 'paiement') and obj.paiement is not None
        except:
            return False


class DemandeCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a new request"""

    class Meta:
        model = Demande
        fields = [
            'utilisateur', 'numero_acte', 'date_etablissement',
            'quantite', 'commune_source', 'commune_cible', 'commentaires'
        ]


class DemandeUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating a request status by an agent"""

    class Meta:
        model = Demande
        fields = ['statut', 'agent_en_charge', 'commentaires']


class DemandeListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for request lists"""
    utilisateur_nom = serializers.CharField(source='utilisateur.nom', read_only=True)  # Plus léger que StringRelatedField
    commune_source = serializers.SlugRelatedField(slug_field='nom', read_only=True)
    commune_cible = serializers.SlugRelatedField(slug_field='nom', read_only=True)

    class Meta:
        model = Demande
        fields = ['id', 'numero_demande', 'utilisateur_nom', 'commune_source', 'commune_cible', 'date_demande', 'statut']


    def get_utilisateur_nom(self, obj):
        """Returns the full name of the user"""
        return f"{obj.utilisateur.nom} {obj.utilisateur.prenoms}"


class EnregistrementSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for Enregistrement model"""
    agent_details = AgentListSerializer(source='agent', read_only=True)

    class Meta:
        model = Enregistrement
        fields = [
            'id', 'agent', 'agent_details',
            'numero_acte', 'date_acte', 'date_enregistrement',
            'nom_enfant', 'prenoms_enfant', 'date_naissance', 'heure_naissance',
            'lieu_naissance', 'sexe', 'nom_pere', 'prenoms_pere',
            'nationalite_pere', 'profession_pere', 'domicile_pere',
            'nom_mere', 'prenoms_mere', 'nationalite_mere',
            'profession_mere', 'domicile_mere', 'mentions_marginales',
            'date_delivrance', 'lieu_delivrance', 'nom_officier_etat_civil',
            'signature_officier', 'fonction_officier', 'sceau_officiel',
            'date_creation', 'date_modification'
        ]
        read_only_fields = ['id', 'date_creation', 'date_modification']


class EnregistrementListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for registration lists"""

    class Meta:
        model = Enregistrement
        fields = [
            'id', 'numero_acte', 'nom_enfant', 'prenoms_enfant',
            'date_naissance', 'date_delivrance'
        ]


class PaiementSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for Paiement model"""
    demande_details = DemandeListSerializer(source='demande', read_only=True)
    demande = serializers.SerializerMethodField()
    class Meta:
        model = Paiement
        fields = [
            'id', 'reference', 'demande', 'demande_details', 'montant',
            'methode', 'telephone', 'id_transaction', 'statut',
            'date_paiement'
        ]
        read_only_fields = ['id', 'reference', 'date_paiement']

    def get_demande(self, obj):
        if obj.demande:
            return obj.demande.numero_demande
        return None


class PaiementCreateSerializer(serializers.ModelSerializer):
    """Serializer for initializing a payment"""

    class Meta:
        model = Paiement
        fields = ['demande', 'montant', 'methode', 'telephone']


class PaiementUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating payment status"""

    class Meta:
        model = Paiement
        fields = ['statut', 'id_transaction']


class RejetSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for Rejet model"""
    demande_details = DemandeListSerializer(source='demande', read_only=True)
    agent_details = AgentListSerializer(source='agent', read_only=True)
    demande = serializers.SerializerMethodField()
    agent = serializers.SerializerMethodField()

    class Meta:
        model = Rejet
        fields = [
            'id', 'motif', 'demande', 'demande_details',
            'agent', 'agent_details', 'procedure_recours',
            'date_rejet', 'delais_recours'
        ]
        read_only_fields = ['id', 'date_rejet']

    def get_demande(self, obj):
        if obj.demande:
            return obj.demande.numero_demande
        return None

    def get_agent(self, obj):
        if obj.agent:
            return f"{obj.agent.nom} {obj.agent.prenoms}"
        return None


class RejetCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a rejection"""

    class Meta:
        model = Rejet
        fields = ['motif', 'demande', 'agent', 'procedure_recours', 'delais_recours']


class JournalSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for Journal model"""
    utilisateur_details = UtilisateurListSerializer(source='utilisateur', read_only=True)
    agent_details = AgentListSerializer(source='agent', read_only=True)
    demande_details = DemandeListSerializer(source='demande', read_only=True)

    class Meta:
        model = Journal
        fields = [
            'id', 'date_action', 'type_action', 'description',
            'utilisateur', 'utilisateur_details', 'agent', 'agent_details',
            'demande', 'demande_details', 'adresse_ip'
        ]
        read_only_fields = ['id', 'date_action']


class JournalCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a journal entry"""

    class Meta:
        model = Journal
        fields = [
            'type_action', 'description', 'utilisateur', 'agent',
            'demande', 'adresse_ip'
        ]


class NotificationSerializer(serializers.ModelSerializer):
    is_for_agent = serializers.SerializerMethodField()
    agent_details = serializers.SerializerMethodField()
    utilisateur_details = UtilisateurListSerializer(source='utilisateur', read_only=True)
    demande_details = DemandeListSerializer(source='demande', read_only=True)

    class Meta:
        model = Notification
        fields = [
            'id', 'titre', 'message', 'type_notification',
            'date_creation', 'est_lu', 'date_lecture',
            'utilisateur', 'utilisateur_details',
            'demande', 'demande_details',
            'is_for_agent', 'agent_details'
        ]
        read_only_fields = ['id', 'date_creation', 'date_lecture']

    def get_is_for_agent(self, obj):
        """Check if the notification is for an agent"""
        return hasattr(obj.utilisateur, 'agent')

    def get_agent_details(self, obj):
        """Get agent details if the user is an agent"""
        if hasattr(obj.utilisateur, 'agent'):
            agent = obj.utilisateur.agent
            return {
                'matricule': agent.matricule,
                'role': agent.role,
                'commune_service': agent.commune_service.nom
            }
        return None

class NotificationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['titre', 'message', 'type_notification', 'utilisateur', 'demande']
        extra_kwargs = {
            'utilisateur': {'required': True}
        }

    def validate_utilisateur(self, value):
        """Validate that the user exists"""
        if not Utilisateur.objects.filter(pk=value.pk).exists():
            raise serializers.ValidationError("L'utilisateur spécifié n'existe pas.")
        return value

class NotificationUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['est_lu']


class LoginSerializer(serializers.Serializer):
    """Serializer for user authentication"""
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})


class AgentLoginSerializer(serializers.Serializer):
    """Serializer for agent authentication"""
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change"""
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(required=True, style={'input_type': 'password'},
                                         validators=[validate_password])
    new_password_confirmation = serializers.CharField(required=True, style={'input_type': 'password'})

    def validate(self, attrs):
        """Validate that new passwords match"""
        if attrs.get('new_password') != attrs.get('new_password_confirmation'):
            raise serializers.ValidationError(
                {"new_password_confirmation": _("Passwords do not match.")}
            )
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request"""
    email = serializers.EmailField(required=True)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation"""
    token = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'}, validators=[validate_password])
    password_confirmation = serializers.CharField(required=True, style={'input_type': 'password'})

    def validate(self, attrs):
        """Validate that passwords match"""
        if attrs.get('password') != attrs.get('password_confirmation'):
            raise serializers.ValidationError(
                {"password_confirmation": _("Passwords do not match.")}
            )
        return attrs


class DemandeStatistiquesSerializer(serializers.Serializer):
    total = serializers.IntegerField(read_only=True)
    en_attente = serializers.IntegerField(read_only=True)
    en_cours = serializers.IntegerField(read_only=True)
    traitees = serializers.IntegerField(read_only=True)
    rejetees = serializers.IntegerField(read_only=True)
    payees = serializers.IntegerField(read_only=True)
    livrees = serializers.IntegerField(read_only=True)

    # Optionnel : S'il faut inclure des métadonnées (ex : période)
    periode = serializers.DictField(read_only=True)

    # Méthode factice
    def create(self, validated_data):
        pass