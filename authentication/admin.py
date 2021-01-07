from django.contrib import admin

# Register your models here.
from .models import User


class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'auth_provider', 'created_at']


admin.site.register(User, UserAdmin)
