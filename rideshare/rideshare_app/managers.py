from django.contrib.auth.models import BaseUserManager


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, role, address, phone_number, **extra_fields):
        if not email:
            raise ValueError("User must have an email address")

        if not role:
            raise ValueError("User must have an role")

        if not address:
            raise ValueError("User must have an address")

        if not phone_number:
            raise ValueError("User must have an phone number")

        email = self.normalize_email(email)
        user = self.model(
            email=email,
            role=role,
            address=address,
            phone_number=phone_number,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", "admin")
        return self.create_user(email, password, role="admin", **extra_fields)
