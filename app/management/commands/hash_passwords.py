from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from app.models import Users

class Command(BaseCommand):
    help = "Hash existing plaintext passwords in the Users table using PBKDF2."

    def handle(self, *args, **options):
        users = Users.objects.all()
        updated = 0
        for user in users:
            pw = user.password or ""
            if not pw.startswith('pbkdf2_'):
                user.password = make_password(pw)
                user.save(update_fields=['password'])
                updated += 1
        if updated:
            self.stdout.write(self.style.SUCCESS(f"Hashed {updated} plaintext password(s)."))
        else:
            self.stdout.write(self.style.WARNING("No plaintext passwords found."))

