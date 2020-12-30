from django.apps import AppConfig
from django.contrib import admin
from .models import SMSVerification


class UsersConfig(AppConfig):
    name = 'users'

    # def ready(self):
    #     import users.signals

