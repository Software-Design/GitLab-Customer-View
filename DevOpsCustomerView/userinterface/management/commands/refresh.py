import datetime
from datetime import timezone
from userinterface.tools.templateHelper import template
from django.core.cache import cache

from django.conf import settings
from django.core.mail import EmailMessage
from django.core.management import BaseCommand, CommandError
from userinterface.models import Project, UserProjectAssignment
from userinterface.tools.viewsHelper import getRepositoryService


class Command(BaseCommand):
    help = "Manually refresh the cache for all projects"

    def handle(self, *args, **options):
        cache.clear()
        projectAssignments = (
            UserProjectAssignment.objects.filter(project__closed=False)
            .order_by("project__name")
            .all()
        )

        for assignment in projectAssignments:
            print("Refreshing project: " + assignment.project.name)
            repService = getRepositoryService(assignment.project)
            glProject = repService.loadProject(
                assignment.project, assignment.access_token
            )
