# -*- coding: utf-8 -*-
import hashlib, random, sys, os, time
from datetime import datetime
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth import login, authenticate

__all__ = ['Nonce', 'Association', 'UserAssociation', 
        'UserPasswordQueueManager', 'UserPasswordQueue']

def get_or_create_unique_user(
    preferred_username = None,
    login_provider_name = None
):
    """retrieves a user by name 
    if such user does not exist, create a new user and make
    username unique throughout the system

    this function monkey patches user object with a new
    boolean attribute - ``name_is_automatic``, which is set
    to True, when user name is automatically created

    return value is a tuple - user object and a boolean
    the second return value is ``True`` if the user is created
    """
    user, created = User.objects.get_or_create(username = preferred_username)
    if created:
        user.name_is_automatic = False
    else:
        #this is a very basic solution and needs more attention
        #have username collision - so make up a more unique user name
        #bug: - if user already exists with the new username - we are in trouble
        new_username = '%s@%s' % (preferred_username, login_provider_name)
        user = User.objects.create_user(new_username, '')
        user.name_is_automatic = True
    return user, created

def create_user_association(sender = None, request = None, user = None, **kwargs):
    """creates user association"""
    assoc = UserAssociation(
                        user = user,
                        provider_name = request.session['login_provider_name']
                    )
    assoc.openid_url = request.session['user_identifier']
    assoc.last_used_timestamp = datetime.now()
    assoc.save()
    #won't be able to re-enter the same view again
    del request.session['login_provider_name']
    del request.session['user_identifier']
    return assoc

def login_the_user(sender = None, request = None, user = None, **kwargs):
    user = authenticate(identifier = user.id, method = 'force')
    login(request, user)

class Nonce(models.Model):
    """ openid nonce """
    server_url = models.CharField(max_length=255)
    timestamp = models.IntegerField()
    salt = models.CharField(max_length=40)

    class Meta:
        db_table = 'django_authopenid_nonce'
    
    def __unicode__(self):
        return u"Nonce: %s" % self.id

    
class Association(models.Model):
    """ association openid url and lifetime """
    server_url = models.TextField(max_length=2047)
    handle = models.CharField(max_length=255)
    secret = models.TextField(max_length=255) # Stored base64 encoded
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.TextField(max_length=64)

    class Meta:
        db_table = 'django_authopenid_association'
    
    def __unicode__(self):
        return u"Association: %s, %s" % (self.server_url, self.handle)

class UserAssociation(models.Model):
    """ 
    model to manage association between openid and user 
    """
    #todo: rename this field so that it sounds good for other methods
    #for exaple, for password provider this will hold password
    openid_url = models.CharField(blank=False, max_length=255)
    user = models.ForeignKey(User)
    #in the future this must be turned into an 
    #association with a Provider record
    #to hold things like login badge, etc
    provider_name = models.CharField(max_length=64, default='unknown')
    last_used_timestamp = models.DateTimeField(null=True)

    class Meta(object):
        db_table = 'django_authopenid_userassociation'
        unique_together = (
                                ('user','provider_name'),
                                ('openid_url', 'provider_name')
                            )
    
    def __unicode__(self):
        return "Openid %s with user %s" % (self.openid_url, self.user)

class UserPasswordQueueManager(models.Manager):
    """ manager for UserPasswordQueue object """
    def get_new_confirm_key(self):
        "Returns key that isn't being used."
        # The random module is seeded when this Apache child is created.
        # Use SECRET_KEY as added salt.
        while 1:
            confirm_key = hashlib.md5("%s%s%s%s" % (
                random.randint(0, sys.maxint - 1), os.getpid(),
                time.time(), settings.SECRET_KEY)).hexdigest()
            try:
                self.get(confirm_key=confirm_key)
            except self.model.DoesNotExist:
                break
        return confirm_key


class UserPasswordQueue(models.Model):
    """
    model for new password queue.
    """
    user = models.ForeignKey(User, unique=True)
    new_password = models.CharField(max_length=30)
    confirm_key = models.CharField(max_length=40)

    objects = UserPasswordQueueManager()

    class Meta:
        db_table = 'django_authopenid_userpasswordqueue'

    def __unicode__(self):
        return self.user.username

from registration import signals
signals.user_registered.connect(create_user_association)
signals.user_registered.connect(login_the_user)
