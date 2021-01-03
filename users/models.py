import jwt
import datetime
import uuid

from django.utils.translation import ugettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField
from datetime import datetime, timedelta
from django.db import models
from django.conf import settings
from django.dispatch import receiver
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.db.models.signals import post_save
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

from django.core.mail import EmailMultiAlternatives
from django_rest_passwordreset.signals import reset_password_token_created


class UUIDModel(AbstractBaseUser, PermissionsMixin):
    """ An abstract base class model that makes primary key `id` as UUID
    instead of default auto incremented number.
    """

    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    class Meta:
        abstract = True


class TimeStampedUUIDModel(UUIDModel):
    """An abstract base class model that provides self-updating
    ``created`` and ``modified`` fields with UUID as primary_key field.
    """

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    modified_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class SMSVerification(TimeStampedUUIDModel):
    security_code = models.CharField(_("Security Code"), max_length=120)
    phone_number = PhoneNumberField(_("Phone Number"))
    session_token = models.CharField(_("Device Session Token"), max_length=500)
    is_verified = models.BooleanField(_("Security Code Verified"), default=False)

    class Meta:
        db_table = "sms_verification"
        verbose_name = _("SMS Verification")
        verbose_name_plural = _("SMS Verifications")
        ordering = ("-modified_at",)
        unique_together = ("security_code", "phone_number", "session_token")

    def __str__(self):
        return "{}: {}".format(str(self.phone_number), self.security_code)


class MyUserManager(BaseUserManager):
    def create_user(self, username, email, phone, password=None):
        if not email:
            raise TypeError("Please, enter your email.")
        if not phone:
            raise TypeError("Please, enter your phone.")

        user = self.model(
            phone=phone,
            username=username,
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(
            username=username,
            email=email,
            phone=self.phone,
            password=password,
        )
        user.is_active = True
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=64)
    last_name = models.CharField(max_length=64)
    username = models.CharField(max_length=64, unique=True, null=True, blank=True)
    email = models.EmailField(unique=True)
    birthday = models.DateField(null=True)
    phone_number = models.CharField(max_length=64, unique=True)
    country = models.CharField(max_length=128, null=True, blank=True)
    zip_code = models.CharField(max_length=32, null=True, blank=True)
    state = models.CharField(max_length=128, null=True, blank=True)
    city = models.CharField(max_length=128, null=True, blank=True)
    address = models.CharField(max_length=128, null=True, blank=True)
    about_me = models.TextField(max_length=512, null=True, blank=True)
    image = models.ImageField(upload_to='users', null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['username', 'password']

    objects = MyUserManager()

    def __str__(self):
        return '%s %s' % (self.first_name, self.last_name)

    @property
    def token(self):
        return self._generate_jwt_token()

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    def _generate_jwt_token(self):
        dt = datetime.now() + timedelta(days=60)
        token = jwt.encode({
            'id': self.pk,
            'exp': dt.utcfromtimestamp(dt.timestamp())
        }, settings.SECRET_KEY, algorithm='HS256')
        return token.decode('utf-8')


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    # send an e-mail to the user
    context = {
        'current_user': reset_password_token.user,
        'username': reset_password_token.user.username,
        'email': reset_password_token.user.email,
        'reset_password_url': "https://vrmates.co/change-password/?token={token}".format(token=reset_password_token.key)
    }


@receiver(post_save, sender=User)
def banned_notifications(sender, instance, created, **kwargs):
    if instance.is_banned:
        instance.is_active = False
        mail_subject = 'Your account has been banned | Vrmates team'
        message = render_to_string('users/account_ban.html', {
            'user': instance.first_name
        })
        to_email = instance.email
        email = EmailMessage(
            mail_subject, message, to=[to_email]
        )
        email.send()
