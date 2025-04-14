from django.test import TestCase
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
from api.models import (
    Utilisateur, Commune, Agent, Demande,
    Enregistrement, Paiement, Rejet, Journal, Notification
)


class UtilisateurTestCase(TestCase):
    """Tests pour le modèle Utilisateur"""

    def setUp(self):
        """Créer un utilisateur de test"""
        self.utilisateur = Utilisateur.objects.create_user(
            email="test@example.com",
            nom="Dupont",
            prenoms="Jean",
            password="motdepasse123",
            telephone="+2250123456789"
        )

    def test_creation_utilisateur(self):
        """Teste la création d'un utilisateur"""
        self.assertEqual(self.utilisateur.email, "test@example.com")
        self.assertEqual(self.utilisateur.nom, "Dupont")
        self.assertEqual(self.utilisateur.prenoms, "Jean")
        self.assertEqual(self.utilisateur.telephone, "+2250123456789")
        self.assertTrue(self.utilisateur.is_active)
        self.assertFalse(self.utilisateur.is_staff)

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        self.assertEqual(str(self.utilisateur), "Dupont Jean")

    def test_email_requis(self):
        """Teste que l'email est requis"""
        with self.assertRaises(ValueError):
            Utilisateur.objects.create_user(
                email="",
                nom="Dupont",
                prenoms="Jean",
                password="motdepasse123"
            )


class CommuneTestCase(TestCase):
    """Tests pour le modèle Commune"""

    def setUp(self):
        """Créer une commune de test"""
        self.commune = Commune.objects.create(
            nom="Abidjan",
            type=Commune.TypeItems.MAIRIE,
            region="Sud",
            adresse_postale="BP 1234",
            telephone="+2250123456789",
            email="mairie.abidjan@example.com"
        )

    def test_creation_commune(self):
        """Teste la création d'une commune"""
        self.assertEqual(self.commune.nom, "Abidjan")
        self.assertEqual(self.commune.type, "mairie")
        self.assertEqual(self.commune.region, "Sud")

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        self.assertEqual(str(self.commune), "Abidjan (mairie)")

    def test_unicite_nom_region(self):
        """Teste l'unicité de la combinaison nom-région"""
        # Tenter de créer une commune avec le même nom et région
        with self.assertRaises(Exception):  # Pourrait être IntegrityError
            Commune.objects.create(
                nom="Abidjan",
                type=Commune.TypeItems.SOUS_PREFECTURE,
                region="Sud",
                telephone="+2250123456780",
                email="autre.abidjan@example.com"
            )


class AgentTestCase(TestCase):
    """Tests pour le modèle Agent"""

    def setUp(self):
        """Créer une commune et un agent de test"""
        self.commune = Commune.objects.create(
            nom="Abidjan",
            type=Commune.TypeItems.MAIRIE,
            region="Sud",
            telephone="+2250123456789",
            email="mairie.abidjan@example.com"
        )

        self.agent = Agent.objects.create(
            username="agent001",
            email="agent@example.com",
            password="motdepasse123",
            nom="Kouamé",
            prenoms="Pierre",
            matricule="MAT123456",
            telephone="+2250123456790",
            commune_service=self.commune,
            poste="Secrétaire",
            role=Agent.RoleItems.AGENT
        )

    def test_creation_agent(self):
        """Teste la création d'un agent"""
        self.assertEqual(self.agent.username, "agent001")
        self.assertEqual(self.agent.email, "agent@example.com")
        self.assertEqual(self.agent.nom, "Kouamé")
        self.assertEqual(self.agent.prenoms, "Pierre")
        self.assertEqual(self.agent.matricule, "MAT123456")
        self.assertEqual(self.agent.poste, "Secrétaire")
        self.assertEqual(self.agent.role, "agent")
        self.assertEqual(self.agent.commune_service, self.commune)

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        self.assertEqual(str(self.agent), "Kouamé Pierre (agent)")


class DemandeTestCase(TestCase):
    """Tests pour le modèle Demande"""

    def setUp(self):
        """Créer une demande de test avec les dépendances requises"""
        self.utilisateur = Utilisateur.objects.create_user(
            email="user@example.com",
            nom="Diallo",
            prenoms="Fatou",
            password="motdepasse123",
            telephone="+2250123456789"
        )

        self.commune_source = Commune.objects.create(
            nom="Abidjan",
            type=Commune.TypeItems.MAIRIE,
            region="Sud",
            telephone="+2250123456789",
            email="mairie.abidjan@example.com"
        )

        self.commune_cible = Commune.objects.create(
            nom="Bouaké",
            type=Commune.TypeItems.MAIRIE,
            region="Centre",
            telephone="+2250123456790",
            email="mairie.bouake@example.com"
        )

        self.agent = Agent.objects.create(
            username="agent002",
            email="agent2@example.com",
            password="motdepasse123",
            nom="Koné",
            prenoms="Ibrahim",
            matricule="MAT654321",
            telephone="+2250123456791",
            commune_service=self.commune_source,
            role=Agent.RoleItems.AGENT
        )

        self.demande = Demande.objects.create(
            utilisateur=self.utilisateur,
            date_etablissement=timezone.now().date() - timedelta(days=365),
            numero_acte="ACT123456",
            quantite=2,
            commune_source=self.commune_source,
            commune_cible=self.commune_cible,
            agent_en_charge=self.agent
        )

    def test_creation_demande(self):
        """Teste la création d'une demande"""
        self.assertEqual(self.demande.utilisateur, self.utilisateur)
        self.assertEqual(self.demande.commune_source, self.commune_source)
        self.assertEqual(self.demande.commune_cible, self.commune_cible)
        self.assertEqual(self.demande.agent_en_charge, self.agent)
        self.assertEqual(self.demande.statut, Demande.StatutDemande.EN_ATTENTE)
        self.assertEqual(self.demande.quantite, 2)

    def test_numero_demande_auto(self):
        """Teste la génération automatique du numéro de demande"""
        self.assertIsNotNone(self.demande.numero_demande)
        self.assertEqual(len(self.demande.numero_demande), 16)

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        expected = f"Demande {self.demande.numero_demande} - {self.utilisateur.nom} (en_attente)"
        self.assertEqual(str(self.demande), expected)


class PaiementTestCase(TestCase):
    """Tests pour le modèle Paiement"""

    def setUp(self):
        """Créer un paiement de test avec les dépendances requises"""
        self.utilisateur = Utilisateur.objects.create_user(
            email="user@example.com",
            nom="Diallo",
            prenoms="Fatou",
            password="motdepasse123",
            telephone="+2250123456789"
        )

        self.commune_source = Commune.objects.create(
            nom="Abidjan",
            type=Commune.TypeItems.MAIRIE,
            region="Sud",
            telephone="+2250123456789",
            email="mairie.abidjan@example.com"
        )

        self.commune_cible = Commune.objects.create(
            nom="Bouaké",
            type=Commune.TypeItems.MAIRIE,
            region="Centre",
            telephone="+2250123456790",
            email="mairie.bouake@example.com"
        )

        self.demande = Demande.objects.create(
            utilisateur=self.utilisateur,
            date_etablissement=timezone.now().date() - timedelta(days=365),
            numero_acte="ACT123456",
            quantite=2,
            commune_source=self.commune_source,
            commune_cible=self.commune_cible
        )

        self.paiement = Paiement.objects.create(
            demande=self.demande,
            montant=Decimal("5000.00"),
            methode=Paiement.MethodePaiement.ORANGE_MONEY,
            telephone="+2250123456789"
        )

    def test_creation_paiement(self):
        """Teste la création d'un paiement"""
        self.assertEqual(self.paiement.demande, self.demande)
        self.assertEqual(self.paiement.montant, Decimal("5000.00"))
        self.assertEqual(self.paiement.methode, "orange_money")
        self.assertEqual(self.paiement.statut, Paiement.StatutPaiement.EN_ATTENTE)

    def test_confirmer_paiement(self):
        """Teste la méthode pour confirmer un paiement"""
        self.paiement.confirmer_paiement(id_transaction="TRX123456")
        self.assertEqual(self.paiement.statut, Paiement.StatutPaiement.PAYE)
        self.assertEqual(self.paiement.id_transaction, "TRX123456")
        self.assertIsNotNone(self.paiement.date_confirmation)

    def test_reference_auto(self):
        """Teste la génération automatique de la référence"""
        self.assertIsNotNone(self.paiement.reference)
        self.assertTrue(self.paiement.reference.startswith("PAY-"))
        self.assertEqual(len(self.paiement.reference), 15)  # "PAY-" + 10 caractères

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        expected = f"Paiement {self.paiement.reference} - 5000.00 (en_attente)"
        self.assertEqual(str(self.paiement), expected)


class EnregistrementTestCase(TestCase):
    """Tests pour le modèle Enregistrement"""

    def setUp(self):
        """Créer un enregistrement de test avec les dépendances requises"""
        self.agent = Agent.objects.create(
            username="agent003",
            email="agent3@example.com",
            password="motdepasse123",
            nom="Touré",
            prenoms="Amadou",
            matricule="MAT789012",
            telephone="+2250123456792",
            commune_service=Commune.objects.create(
                nom="Yamoussoukro",
                type=Commune.TypeItems.MAIRIE,
                region="Centre",
                telephone="+2250123456793",
                email="mairie.yam@example.com"
            ),
            role=Agent.RoleItems.AGENT
        )

        self.enregistrement = Enregistrement.objects.create(
            agent=self.agent,
            numero_acte="ACT789012",
            date_acte=timezone.now().date() - timedelta(days=3650),
            date_enregistrement=timezone.now().date() - timedelta(days=3650),
            nom_enfant="Koffi",
            prenoms_enfant="Aya Marie",
            date_naissance=timezone.now().date() - timedelta(days=3650),
            lieu_naissance="Yamoussoukro",
            sexe="femme",
            nom_pere="Koffi",
            prenoms_pere="Kouadio",
            nationalite_pere="Ivoirienne",
            profession_pere="Ingénieur",
            domicile_pere="Yamoussoukro",
            nom_mere="Bakayoko",
            prenoms_mere="Aminata",
            nationalite_mere="Ivoirienne",
            profession_mere="Enseignante",
            domicile_mere="Yamoussoukro",
            date_delivrance=timezone.now().date(),
            lieu_delivrance="Yamoussoukro",
            nom_officier_etat_civil="Traoré Karim"
        )

    def test_creation_enregistrement(self):
        """Teste la création d'un enregistrement"""
        self.assertEqual(self.enregistrement.agent, self.agent)
        self.assertEqual(self.enregistrement.numero_acte, "ACT789012")
        self.assertEqual(self.enregistrement.nom_enfant, "Koffi")
        self.assertEqual(self.enregistrement.prenoms_enfant, "Aya Marie")
        self.assertEqual(self.enregistrement.sexe, "femme")

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        expected = f"Koffi Aya Marie - {self.enregistrement.date_naissance}"
        self.assertEqual(str(self.enregistrement), expected)


class RejetTestCase(TestCase):
    """Tests pour le modèle Rejet"""

    def setUp(self):
        """Créer un rejet de test avec les dépendances requises"""
        self.utilisateur = Utilisateur.objects.create_user(
            email="user@example.com",
            nom="Diallo",
            prenoms="Fatou",
            password="motdepasse123",
            telephone="+2250123456789"
        )

        self.commune = Commune.objects.create(
            nom="Abidjan",
            type=Commune.TypeItems.MAIRIE,
            region="Sud",
            telephone="+2250123456789",
            email="mairie.abidjan@example.com"
        )

        self.agent = Agent.objects.create(
            username="agent004",
            email="agent4@example.com",
            password="motdepasse123",
            nom="Sanogo",
            prenoms="Mamadou",
            matricule="MAT101112",
            telephone="+2250123456794",
            commune_service=self.commune,
            role=Agent.RoleItems.AGENT
        )

        self.demande = Demande.objects.create(
            utilisateur=self.utilisateur,
            date_etablissement=timezone.now().date() - timedelta(days=365),
            numero_acte="ACT999888",
            quantite=1,
            commune_source=self.commune,
            commune_cible=self.commune
        )

        self.rejet = Rejet.objects.create(
            motif="Informations incomplètes ou incorrectes",
            demande=self.demande,
            agent=self.agent,
            procedure_recours="Veuillez corriger les informations et soumettre à nouveau."
        )

    def test_creation_rejet(self):
        """Teste la création d'un rejet"""
        self.assertEqual(self.rejet.motif, "Informations incomplètes ou incorrectes")
        self.assertEqual(self.rejet.demande, self.demande)
        self.assertEqual(self.rejet.agent, self.agent)

        # Vérifie que le statut de la demande a été mis à jour
        self.demande.refresh_from_db()
        self.assertEqual(self.demande.statut, Demande.StatutDemande.REJETE)

    def test_delais_recours(self):
        """Teste la définition du délai de recours"""
        self.assertGreater(self.rejet.delais_recours, timezone.now())

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        expected = f"Rejet de la demande {self.demande.numero_demande} par {self.agent.nom}"
        self.assertEqual(str(self.rejet), expected)


class JournalTestCase(TestCase):
    """Tests pour le modèle Journal"""

    def setUp(self):
        """Créer une entrée de journal de test"""
        self.utilisateur = Utilisateur.objects.create_user(
            email="user@example.com",
            nom="Diallo",
            prenoms="Fatou",
            password="motdepasse123",
            telephone="+2250123456789"
        )

        self.commune = Commune.objects.create(
            nom="Abidjan",
            type=Commune.TypeItems.MAIRIE,
            region="Sud",
            telephone="+2250123456789",
            email="mairie.abidjan@example.com"
        )

        self.demande = Demande.objects.create(
            utilisateur=self.utilisateur,
            date_etablissement=timezone.now().date() - timedelta(days=365),
            numero_acte="ACT777666",
            quantite=1,
            commune_source=self.commune,
            commune_cible=self.commune
        )

        self.journal = Journal.objects.create(
            type_action=Journal.TypeAction.CREATION,
            description="Création d'une nouvelle demande d'extrait de naissance",
            utilisateur=self.utilisateur,
            demande=self.demande,
            adresse_ip="192.168.1.1"
        )

    def test_creation_journal(self):
        """Teste la création d'une entrée de journal"""
        self.assertEqual(self.journal.type_action, "creation")
        self.assertEqual(self.journal.utilisateur, self.utilisateur)
        self.assertEqual(self.journal.demande, self.demande)
        self.assertEqual(self.journal.adresse_ip, "192.168.1.1")

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        self.assertIn(self.journal.type_action, str(self.journal))
        self.assertIn(str(self.utilisateur), str(self.journal))


class NotificationTestCase(TestCase):
    """Tests pour le modèle Notification"""

    def setUp(self):
        """Créer une notification de test"""
        self.utilisateur = Utilisateur.objects.create_user(
            email="user@example.com",
            nom="Diallo",
            prenoms="Fatou",
            password="motdepasse123",
            telephone="+2250123456789"
        )

        self.notification = Notification.objects.create(
            titre="Confirmation de demande",
            message="Votre demande a été reçue et est en cours de traitement.",
            type_notification=Notification.TypeNotification.INFO,
            utilisateur=self.utilisateur
        )

    def test_creation_notification(self):
        """Teste la création d'une notification"""
        self.assertEqual(self.notification.titre, "Confirmation de demande")
        self.assertEqual(self.notification.message, "Votre demande a été reçue et est en cours de traitement.")
        self.assertEqual(self.notification.type_notification, "info")
        self.assertEqual(self.notification.utilisateur, self.utilisateur)
        self.assertFalse(self.notification.est_lu)

    def test_marquer_comme_lu(self):
        """Teste la méthode pour marquer comme lu"""
        self.notification.marquer_comme_lu()
        self.assertTrue(self.notification.est_lu)
        self.assertIsNotNone(self.notification.date_lecture)

    def test_str_representation(self):
        """Teste la représentation sous forme de chaîne"""
        self.assertIn("Confirmation de demande", str(self.notification))
        self.assertIn(str(self.utilisateur), str(self.notification))