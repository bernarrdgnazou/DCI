from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from .models import Utilisateur, Agent

class MultiModelAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Essayer Utilisateur
        user = Utilisateur.objects.filter(email=username).first()
        if user and user.check_password(password):
            return user

        # Essayer Agent
        agent = Agent.objects.filter(email=username).first()
        if agent and agent.check_password(password):
            return agent

        return None  # Échec de l'authentification

    def get_user(self, user_id):
        # Vérifier d'abord Utilisateur, puis Agent
        user = Utilisateur.objects.filter(pk=user_id).first()
        if user:
            return user
        return Agent.objects.filter(pk=user_id).first()