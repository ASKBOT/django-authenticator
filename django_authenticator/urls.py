# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, url
from django.utils.translation import ugettext as _

urlpatterns = patterns('django_authenticator.views',
    # yadis rdf
    url(r'^yadis.xrdf$', 'xrdf', name='yadis_xrdf'),
     # manage account registration
    url(r'^%s$' % _('signin/'), 'signin', name='user_signin'),
    url(r'^%s$' % _('signout/'), 'signout', name='user_signout'),
    #this view is "complete-openid" signin
    url(r'^%s%s$' % (_('signin/'), _('complete-openid/')), 'complete_openid_signin', 
        name='user_complete_openid_signin'),
    url(
        r'^%s%s$' % (_('signin/'), _('complete-oauth/')),
        'complete_oauth_signin', 
        name='user_complete_oauth_signin'
    ),
    url(r'^%s$' % _('logout/'), 'logout_page', name='logout'),
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
