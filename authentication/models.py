from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp

from .formatchecker import ContentTypeRestrictedFileField
from phone.models import TimestampedModel


class UserManager(BaseUserManager):
    def create_user(self, phone, email, password=None):
        if phone is None:
            raise TypeError('Users should have phone')
        if email is None:
            raise TypeError('Users should have email')

        user = self.model(phone=phone, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, phone, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(phone, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                  'twitter': 'twitter', 'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin, TimestampedModel):
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    company = models.CharField(max_length=255, unique=True, db_index=True)
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    address = models.CharField(max_length=255)

    avatar = ContentTypeRestrictedFileField(
        upload_to='users/uploads/%Y/%m/%d/',
        content_types=['image/jpeg', 'image/png', 'image/jpg'],
        null=True, blank=True)

    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email')
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone']

    key = models.CharField(max_length=100, unique=True, blank=True)

    enable_authenticator = models.BooleanField(default=False)
    objects = UserManager()

    def __str__(self):
        return self.email

    def get_short_name(self):
        return self.first_name

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    def authenticate(self, otp):
        provided_otp = 0
        try:
            provided_otp = int(otp)
        except:
            return False

        t = pyotp.TOTP(self.key, interval=300)
        return t.verify(provided_otp)
