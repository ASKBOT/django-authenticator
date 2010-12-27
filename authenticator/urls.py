# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, url
from django.utils.translation import ugettext as _
from django.conf import settings

urlpatterns = patterns('askbot.deps.django_authopenid.views',
    # yadis rdf
    url(r'^yadis.xrdf$', 'xrdf', name='yadis_xrdf'),
     # manage account registration
    url(r'^%s$' % _('signin/'), 'signin', name='user_signin'),
    url(r'^%s%s$' % (_('signin/'),_('newquestion/')), 'signin', kwargs = {'newquestion':True}, name='user_signin_new_question'),
    url(r'^%s%s$' % (_('signin/'),_('newanswer/')), 'signin', kwargs = {'newanswer':True}, name='user_signin_new_answer'),
    url(r'^%s$' % _('signout/'), 'signout', name='user_signout'),
    #this view is "complete-openid" signin
    url(r'^%s%s$' % (_('signin/'), _('complete/')), 'complete_signin', 
        name='user_complete_signin'),
    url(
        r'^%s%s$' % (_('signin/'), _('complete-oauth/')),
        'complete_oauth_signin', 
        name='user_complete_oauth_signin'
    ),
    url(r'^%s$' % _('register/'), 'register', name='user_register'),
    url(
        r'^%s$' % _('signup/'),
        'signup_with_password',
        name='user_signup_with_password'
    ),
    #these two commeted out urls should work only with EMAIL_VALIDATION=True
    #but the setting is disabled right now
    #url(r'^%s%s$' % (_('email/'), _('sendkey/')), 'send_email_key', name='send_email_key'),
    #url(r'^%s%s(?P<id>\d+)/(?P<key>[\dabcdef]{32})/$' % (_('email/'), _('verify/')), 'verifyemail', name='user_verifyemail'),
    url(r'^%s(?P<key>[\dabcdef]{32})?$' % _('recover/'), 'account_recover', name='user_account_recover'),
    url(
        r'^delete_login_method/$',#this method is ajax only
        'delete_login_method',
        name ='delete_login_method'
    ),
)
