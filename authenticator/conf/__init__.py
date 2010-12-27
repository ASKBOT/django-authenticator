#import these to compile code and install values
import askbot.conf.minimum_reputation
import askbot.conf.vote_rules
import askbot.conf.reputation_changes
import askbot.conf.email
import askbot.conf.forum_data_rules
import askbot.conf.flatpages
import askbot.conf.site_settings
import askbot.conf.external_keys
#import askbot.conf.skin_counter_settings
import askbot.conf.skin_general_settings
import askbot.conf.user_settings
import askbot.conf.markup
import askbot.conf.social_sharing
import askbot.conf.badges

#import main settings object
from askbot.conf.settings_wrapper import settings

from django.conf import settings as django_settings
def should_show_sort_by_relevance():
    """True if configuration support sorting
    questions by search relevance
    """
    return (django_settings.DATABASE_ENGINE == 'postgresql_psycopg2')
