"""
Settings for askbot data display and entry
"""
from askbot.conf.settings_wrapper import settings
from askbot.deps.livesettings import ConfigurationGroup, BooleanValue, IntegerValue
from askbot.deps.livesettings import StringValue
from django.utils.translation import ugettext as _
from askbot import const

FORUM_DATA_RULES = ConfigurationGroup(
                        'FORUM_DATA_RULES',
                        _('Settings for askbot data entry and display')
                    )

settings.register(
    BooleanValue(
        FORUM_DATA_RULES,
        'WIKI_ON',
        default=True,
        description=_('Check to enable community wiki feature')
    )
)

settings.register(
    IntegerValue(
        FORUM_DATA_RULES,
        'MAX_TAG_LENGTH',
        default=20,
        description=_('Maximum length of tag (number of characters)')
    )
)

settings.register(
    IntegerValue(
        FORUM_DATA_RULES,
        'MAX_COMMENTS_TO_SHOW',
        default=5,
        description=_(
            'Default max number of comments to display under posts'
        )
    )
)

settings.register(
    IntegerValue(
        FORUM_DATA_RULES,
        'MAX_COMMENT_LENGTH',
        default=300,
        description=_(
                'Maximum comment length, must be < %(max_len)s'
            ) % {'max_len': const.COMMENT_HARD_MAX_LENGTH }
    )
)

settings.register(
    IntegerValue(
        FORUM_DATA_RULES,
        'MIN_SEARCH_WORD_LENGTH',
        default=4,
        description=_('Minimum length of search term for Ajax search'),
        help_text=_('Must match the corresponding database backend setting'),
    )
)

settings.register(
    IntegerValue(
        FORUM_DATA_RULES,
        'MAX_TAGS_PER_POST',
        default=5,
        description=_('Maximum number of tags per question')
    )
)

#todo: looks like there is a bug in askbot.deps.livesettings 
#that does not allow Integer values with defaults and choices
settings.register(
    StringValue(
        FORUM_DATA_RULES,
        'DEFAULT_QUESTIONS_PAGE_SIZE',
        choices=const.PAGE_SIZE_CHOICES,
        default='30',
        description=_('Number of questions to list by default')
    )
)

settings.register(
    StringValue(
        FORUM_DATA_RULES,
        'UNANSWERED_QUESTION_MEANING',
        choices=const.UNANSWERED_QUESTION_MEANING_CHOICES,
        default='NO_ACCEPTED_ANSWERS',
        description=_('What should "unanswered question" mean?')
    )
)
