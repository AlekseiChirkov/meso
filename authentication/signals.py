import pyotp
from django.dispatch import receiver
from django.db.models.signals import pre_save

from .models import User


def generate_key():
    key = pyotp.random_base32()
    if is_unique(key):
        return key
    generate_key()


def is_unique(key):
    try:
        User.objects.get(key=key)
    except User.DoesNotExist:
        return True
    return False


@receiver(pre_save, sender=User)
def create_key(sender, instance, **kwargs):
    if not instance.key:
        instance.key = generate_key()
