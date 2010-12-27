from django.core.management.base import NoArgsCommand
from django.db import transaction
from askbot import models
import sys

class Command(NoArgsCommand):
    @transaction.commit_manually
    def handle_noargs(self, **options):
        tags = models.Tag.objects.all()
        count = 0
        print "Searching for unused tags:",
        total = tags.count()
        deleted_tags = list()
        for tag in tags:
            if tag.questions.all().count() == 0:
                deleted_tags.append(tag.name)
                tag.delete()
            transaction.commit()
            count += 1
            sys.stdout.write('%6.2f%%' % (100*float(count)/float(total)))
            sys.stdout.flush()
            sys.stdout.write('\b'*7)
        sys.stdout.write('\n')

        if deleted_tags:
            found_count = len(deleted_tags)
            if found_count == 1:
                print "Found an unused tag %s" % deleted_tags[0]
            else:
                sys.stdout.write("Found %d unused tags" % found_count)
                if found_count > 50:
                    print ", first 50 are:",
                    print ', '.join(deleted_tags[:50]) + '.'
                else:
                    print ": " + ', '.join(deleted_tags) + '.'
            print "Deleted."
        else:
            print "Did not find any."

