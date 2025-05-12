from app.models import Users
from django.contrib.auth.backends import BaseBackend

class UsersAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            user = Users.objects.get(username=username, password=password)
            return user  
        except Users.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return Users.objects.get(pk=user_id)
        except Users.DoesNotExist:
            return None

