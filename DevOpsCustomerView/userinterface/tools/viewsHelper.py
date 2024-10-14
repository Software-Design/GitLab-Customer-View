# Purpose of this file:
# This file provides some helping functions primary for the views.py to prevent redundancy

from typing import Union

from django.core.handlers.wsgi import WSGIRequest
from django.http import Http404, HttpResponse
from userinterface.models import Project, TeamMember

from .gitlabCache import gitlabServiceCache
from .githubCache import githubServiceCache

from typing import Union
from django.core.handlers.wsgi import WSGIRequest
from django.http import Http404, HttpResponse
from django.template import loader


def get_project(request: WSGIRequest, project_id: int) -> Union[dict, HttpResponse]:
    """
    Get the project (currently only GitLab or GitHub project) from the cache.

    Raises:
        Http404: If the requested project does not exist or is not linked to the requesting user.
    """
    project = Project.objects.filter(
        project_identifier=project_id, closed=False
    ).first()

    if not request.user.is_authenticated or not project:
        raise Http404

    if request.user.is_staff:
        has_access = True
    else:
        team_memberships = TeamMember.objects.filter(user=request.user).values_list(
            "team", flat=True
        )
        has_access = project.teams.filter(id__in=team_memberships).exists()

    if not has_access:
        raise Http404

    rep_service = getRepositoryService(project)
    project_data = rep_service.loadProject(project, project.access_token)

    if "error" in project_data:
        if "404" in project_data["error"]:
            raise Http404
        else:
            template = loader.get_template("404.html")
            return HttpResponse(template.render({**project_data}, request))

    return project_data


def getRepositoryService(project: Project):
    if project.repository_service == Project.RepositoryServiceTypes.GITLAB:
        return gitlabServiceCache()
    elif project.repository_service == Project.RepositoryServiceTypes.GITHUB:
        return githubServiceCache()
