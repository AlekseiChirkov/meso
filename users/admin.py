# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from django.contrib import admin

from .models import User, Rating, SMSVerification


class MyUserAdmin(admin.ModelAdmin):
    list_display = ['id', 'first_name', 'last_name', 'username', 'email', 'points', 'avg_rating', 'rating_count',
                    'avg_rating_last_ten', 'canceled_posts', 'created_posts', 'is_active']
    list_display_links = ['id', 'first_name', 'last_name', 'username']
    list_filter = ['is_active']
    search_fields = ['email', 'first_name', 'last_name']

    class Meta:
        model = User


class RatingAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Rating._meta.fields]

    class Meta:
        model = Rating


class SMSVerificationAdmin(admin.ModelAdmin):
    list_display = ("id", "security_code", "phone_number", "is_verified", "created_at")
    search_fields = ("phone_number",)
    ordering = ("phone_number",)
    readonly_fields = (
        "security_code",
        "phone_number",
        "session_token",
        "is_verified",
        "created_at",
        "modified_at",
    )

admin.site.register(User, MyUserAdmin)
admin.site.register(Rating, RatingAdmin)
admin.site.register(SMSVerificationAdmin)

