import datetime
from datetime import timezone
from userinterface.tools.templateHelper import template

from django.conf import settings
from django.core.mail import EmailMessage
from django.core.management import BaseCommand, CommandError
from userinterface.models import Project, UserProjectAssignment
from userinterface.tools.viewsHelper import getRepositoryService


class Command(BaseCommand):
    help = "Send notification mails to users (should run as cron job once a day). Default notify about changes since last run, or at max the last <maxdays> days. python manage.py sendnotifications --maxdays 3"

    def add_arguments(self, parser):
        parser.add_argument(
            "-maxdays",
            "--maxdays",
            type=int,
            help="If last run is past longer than maxdays, than limit notify to that range.",
        )

    def handle(self, *args, **options):
        maxdays = options["maxdays"]
        if not maxdays:
            maxdays = 3
        # As we use the permissions from every user, we have to check for every user if there is a change for him/her
        # go through all projects (only active)
        # check all changes other than the user the notification is send to
        # send mail with info about project and changes (issues changed)

        notifications = self.sendNotifications(maxdays)

        self.stdout.write(
            "command executed and %s notifications sent" % len(notifications)
        )

    def sendNotifications(self, maxDays):
        projectWithChanges = []

        allProjects = Project.objects.filter(closed=False, inactive=False)
        for project in allProjects:
            sinceDateMax = datetime.datetime.now() - datetime.timedelta(days=maxDays)
            sinceLastRun = (
                datetime.datetime.now(timezone.utc) - project.notificationLastRun
            )
            sinceDate = project.notificationLastRun
            if datetime.timedelta(days=maxDays) < sinceLastRun:
                sinceDate = sinceDateMax

            allProjectAssignments = UserProjectAssignment.objects.filter(
                project=project
            )
            for projectAssignment in allProjectAssignments:
                repService = getRepositoryService(projectAssignment.project)
                lastUpdate = repService.lastUpdate(
                    projectAssignment.project, projectAssignment.access_token
                )
                projectObject = repService.loadProject(
                    projectAssignment.project, projectAssignment.access_token
                )
                if lastUpdate > sinceDate:
                    projectWithChanges.append(projectObject)
                    break

        emailAddresses = []
        for project in projectWithChanges:
            projectUsers = (
                UserProjectAssignment.objects.filter(
                    project=project["localProject"], enable_notifications=True
                )
                .order_by("user")
                .all()
            )
            for projectUser in projectUsers:
                if len(projectUser.user.email) > 0:
                    self.sendNotificationToUser(projectUser, project)
                    emailAddresses.append(projectUser.user.email)

        # update lastRun date
        allProjects = Project.objects.filter(closed=False, inactive=False)
        for project in allProjects:
            project.notificationLastRun = datetime.datetime.now(timezone.utc)
            project.save()

        return emailAddresses

    # def sendNotificationsWorking():
    #     maxDays = 3
    #
    #     projectWithChanges = []
    #
    #     # ToDo both repositories
    #     allProjects = Project.objects.filter(closed=False, inactive=False, repositoryService=1)
    #     nextProject = False
    #     for project in allProjects:
    #         # if there are changes detected, continue with next project
    #         if nextProject:
    #             nextProject = False
    #             continue
    #
    #         # check if there are changes with user permissions, end if changes detected
    #         allProjectAssignments = UserProjectAssignment.objects.filter(project=project)
    #         for projectAssignment in allProjectAssignments:
    #             repService = getRepositoryService(projectAssignment.project)
    #             glProject = repService.loadProject(projectAssignment.project, projectAssignment.access_token)
    #             # ToDo add filter since maxdays
    #             sinceDateMax = datetime.datetime.now() - datetime.timedelta(days=maxDays)
    #             sinceLastRun = datetime.datetime.now(timezone.utc) - project.notificationLastRun
    #             sinceDate = project.notificationLastRun
    #             if (datetime.timedelta(days=maxDays) < sinceLastRun):
    #                 sinceDate = sinceDateMax
    #             sinceDate = sinceDate - datetime.timedelta(days=1)
    #             projectEvents = glProject['remoteInstance'].events.list(after=sinceDate.strftime('%Y-%m-%d'))
    #             if (len(projectEvents) > 0):
    #                 for projectEvent in projectEvents:
    #                     if (timezone.make_aware(parse_iso(projectEvent.created_at),
    #                                             timezone.utc) > project.notificationLastRun):
    #                         projectWithChanges.append(glProject)
    #                         nextProject = True
    #                         break
    #
    #     emailAddresses = []
    #     for project in projectWithChanges:
    #         # project.notificationLastRun = datetime.datetime.now()
    #         # project.save()
    #
    #         projectUsers = UserProjectAssignment.objects.filter(project=project['localProject'],
    #                                                             enable_notifications=True).order_by('user').all()
    #         for projectUser in projectUsers:
    #             if (len(projectUser.user.email) > 0):
    #                 sendNotificationToUser(projectUser, project)
    #                 emailAddresses.append(projectUser.user.email)
    #
    #     return emailAddresses

    def sendNotificationToUser(self, projectUser, project):
        message = template("mail/notification").render(
            {
                "project": project,
                "baseUrl": settings.INTERFACE_URL,
            }
        )
        mail = EmailMessage(
            subject="News for " + project["localProject"].name,
            body=message,
            to=[projectUser.user.email],
            from_email=settings.EMAIL_FROM,
        )
        mail.content_subtype = "html"
        return mail.send()
