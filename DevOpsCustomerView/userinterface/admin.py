from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
from .models import (
    CustomerCompany,
    CustomerUser,
    DownloadableFile,
    Project,
    Team,
    TeamMember,
)


class PeopleAdmin(ImportExportModelAdmin):
    list_display = ("get_name", "get_teams", "get_email", "role")

    def get_name(self, obj: TeamMember) -> str:
        return obj.user.username

    get_name.admin_order_field = "user__username"
    get_name.short_description = "Name"

    def get_email(self, obj: TeamMember) -> str:
        return obj.user.email

    get_email.admin_order_field = "user__email"
    get_email.short_description = "Email"

    def get_teams(self, obj: TeamMember) -> str:
        return ", ".join(team.name for team in obj.teams.all())

    get_teams.short_description = "Teams"


class AssignmentAdmin(ImportExportModelAdmin):
    list_display = ("get_team_names", "project")

    def get_team_names(self, assignment: Project) -> str:
        team_names = [team.name for team in assignment.teams.all()]
        return ", ".join(team_names) if team_names else "No Teams Assigned"

    get_team_names.short_description = "Team Names"


class ProjectAdmin(ImportExportModelAdmin):
    list_display = (
        "name",
        "first_email_address",
        "project_identifier",
    )
    exclude = ("private_url_hash",)


class DownloadableFileAdmin(ImportExportModelAdmin):
    list_display = ("name", "project")


class CustomerCompanyAdmin(ImportExportModelAdmin):
    list_display = ("name", "contact_email", "contact_phone")


class CustomerUserAdmin(ImportExportModelAdmin):
    list_display = (
        "get_username",
        "customer_company",
        "enable_notifications",
        "can_handle_contracts",
    )

    def get_username(self, obj: CustomerUser) -> str:
        return obj.user.username

    get_username.admin_order_field = "user__username"
    get_username.short_description = "Username"


class TeamAdmin(ImportExportModelAdmin):
    list_display = ("name", "description")


admin.site.register(CustomerCompany, CustomerCompanyAdmin)
admin.site.register(CustomerUser, CustomerUserAdmin)
admin.site.register(DownloadableFile, DownloadableFileAdmin)
admin.site.register(Project, ProjectAdmin)
admin.site.register(Team, TeamAdmin)
admin.site.register(TeamMember, PeopleAdmin)
