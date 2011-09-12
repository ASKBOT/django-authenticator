# -*- coding: utf-8 -*-

from django.contrib import admin
from django_authenticator.models import UserAssociation


class UserAssociationAdmin(admin.ModelAdmin):
    """User association admin class"""
admin.site.register(UserAssociation, UserAssociationAdmin)