import datetime
import os
from typing import Union, Dict, Any

import pdfkit
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.handlers.wsgi import WSGIRequest
from django.core.mail import EmailMessage
from django.http import HttpResponse, HttpResponseRedirect, FileResponse, Http404
from django.shortcuts import redirect, get_object_or_404
from django.template import Context
from django.template.loader import get_template
from django.utils.translation import gettext as _
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.encoding import iri_to_uri

from .models import *
from .templatetags.dates import parse_date, parse_iso
from .tools.templateHelper import template
from .tools.viewsHelper import get_project, getRepositoryService
from .tools.sendMail import sendingEmail


def index(request: WSGIRequest) -> Union[HttpResponseRedirect, HttpResponse]:
    """
    Handles the requests for /
    Provides the login mechanism to authenticate users
    """

    if request.user.is_authenticated:
        return redirect("/overview/")

    if request.method == "POST" and request.POST.get("email"):
        return handle_login(request)

    return render_login_page(request)


def handle_login(request: WSGIRequest) -> HttpResponseRedirect:
    """
    Handles the login process for the user
    """
    requesting_user = User.objects.filter(email=request.POST["email"]).first()
    username = getattr(requesting_user, "username", request.POST["email"])
    user = authenticate(request, username=username, password=request.POST["password"])

    if user:
        login(request, user)
        redirect_url = request.GET.get("next")
        if url_has_allowed_host_and_scheme(redirect_url, None):
            return redirect(iri_to_uri(redirect_url))
        return redirect("/overview/")

    return redirect("/?error=invalid")


def render_login_page(request: WSGIRequest) -> HttpResponse:
    """
    Renders the login page
    """
    teams = Team.objects.all()
    return HttpResponse(template("login").render({"teams": teams}, request))


def loggingout(request: WSGIRequest) -> HttpResponseRedirect:
    """
    Handles the requests for /logout
    Logging out the user and redirects him to the index page
    """

    logout(request)
    return redirect("/")


@login_required
def userSettings(request: WSGIRequest, slug: str, id: int) -> HttpResponse:
    glProject = get_project(request, id)
    # projectAssignment = UserProjectAssignment.objects.filter(
    #     project=glProject["localProject"], user=request.user
    # ).first()

    if request.POST:
        print(glProject)
    #     projectAssignment.enable_notifications = False
    #     if request.POST.get("enable_notifications"):
    #         projectAssignment.enable_notifications = True
    #     projectAssignment.save()

    # return HttpResponse(
    #     template("project/userSettings").render(
    #         {"enable_notifications": projectAssignment.enable_notifications}, request
    #     )
    # )


@login_required
@staff_member_required
def reportOverview(request: WSGIRequest) -> HttpResponse:
    """
    Handles the requests for /report
    Gets all projects to show on the page
    """

    members = TeamMember.objects.all()

    active_projects = []
    projects = Project.objects.filter(closed=False).order_by("name").distinct()

    for project in projects:
        rep_service = getRepositoryService(project)
        gl_project = rep_service.loadProject(project, project.access_token)
        if gl_project not in active_projects:
            active_projects.append(gl_project)

    return HttpResponse(
        template("report/view").render(
            {"members": members, "activeProjects": active_projects}, request
        )
    )


from typing import List


@login_required
def projectList(request: WSGIRequest) -> HttpResponse:
    """
    Handles the requests for /overview
    Gets all projects to show on the page
    """
    project_assignments: List[Project] = Project.objects.filter(closed=False).order_by(
        "name"
    )

    if not request.user.is_staff:
        customer_memberships = CustomerCompany.objects.filter(
            customeruser__user=request.user
        ).values_list("id", flat=True)
        project_assignments = project_assignments.filter(
            customer_company__in=customer_memberships
        )

    seen_projects = set()
    active_projects = []
    inactive_projects = []

    for project in project_assignments:
        rep_service = getRepositoryService(project)
        gl_project = rep_service.loadProject(project, project.access_token)

        local_project = gl_project["localProject"]
        pk = (
            local_project.get("pk")
            if isinstance(local_project, dict)
            else getattr(local_project, "pk", None)
        )

        if pk not in seen_projects:
            seen_projects.add(pk)
            if project.inactive:
                inactive_projects.append(gl_project)
            else:
                active_projects.append(gl_project)

    return HttpResponse(
        template("project/list").render(
            {"inactiveProjects": inactive_projects, "activeProjects": active_projects},
            request,
        )
    )


def projectPublic(request: WSGIRequest, slug: str, id: int, hash: str) -> HttpResponse:
    """
    Generate an overview for a project that is accessible without having an account.
    """
    project = get_object_or_404(
        Project, project_identifier=id, private_url_hash=hash, closed=False
    )

    if not project.public_overview_password:
        return HttpResponse("Project not found or access restricted", status=404)

    if request.method == "POST" and request.POST.get("password"):
        if request.POST["password"] == project.public_overview_password:
            request.session["password"] = request.POST["password"]
        else:
            return redirect(f"/project/{slug}/{id}/{hash}?error=invalid")

    if request.GET.get("error"):
        return render(request, "project/public.html", {"project": project})

    if (
        not request.session.get("password")
        or request.session["password"] != project.public_overview_password
    ):
        return redirect(f"/project/{slug}/{id}/{hash}?error=loginrequired")

    first_milestone_start = None
    last_milestone_end = None

    for milestone in project.allMilestones.all():
        if milestone.start_date and milestone.due_date:
            start = parse_date(str(milestone.start_date))
            end = parse_date(str(milestone.due_date))
            if not milestone.expired or (
                milestone.expired and (end - start).days < 365
            ):
                if first_milestone_start is None or start < first_milestone_start:
                    first_milestone_start = start
                if last_milestone_end is None or end > last_milestone_end:
                    last_milestone_end = end

    days_between = 0
    if last_milestone_end and first_milestone_start:
        days_between = (last_milestone_end - first_milestone_start).days

    rep_service = getRepositoryService(project)
    gl_project = rep_service.loadProject(project, project.access_token)

    context = {
        "project": project,
        "first_milestone_start": first_milestone_start,
        "last_milestone_end": last_milestone_end,
        "days_between": days_between,
        "gl_project": gl_project,
    }

    return render(request, "project/public.html", context)


@login_required
def projectView(request, slug: str, id: int) -> HttpResponse:

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    firstMilestoneStart = None
    lastMilestoneEnd = None

    for milestone in glProject["allMilestones"]:
        if milestone.start_date and milestone.start_date != "?" and milestone.due_date:
            start = milestone.start_date
            end = milestone.due_date
            if milestone.expired == False or (
                milestone.expired == True and (end - start).days < 365
            ):
                if firstMilestoneStart == None or start < firstMilestoneStart:
                    firstMilestoneStart = start
                if lastMilestoneEnd == None or end > lastMilestoneEnd:
                    lastMilestoneEnd = end

    daysbetween = 0
    if lastMilestoneEnd and firstMilestoneStart:
        daysbetween = (lastMilestoneEnd - firstMilestoneStart).days

    return HttpResponse(
        template("project/view").render(
            glProject | {"daysbetween": daysbetween}, request
        )
    )


@login_required
def issueList(request, slug, id):
    """
    Handles the requests for /project/<slug:slug>/<int:id>/issues/
    Shows a paginated list of issues in this project
    """

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    repService = getRepositoryService(glProject["localProject"])
    glProject["issues"] = repService.loadIssues(
        glProject["localProject"],
        glProject["remoteInstance"],
        page=request.GET.get("page", 1),
        status=request.GET.get("status", None),
        label=request.GET.get("label", None),
    )

    return HttpResponse(template("issue/list").render(glProject, request))


@login_required
def issueCreate(
    request: WSGIRequest, slug: str, id: int
) -> Union[HttpResponseRedirect, HttpResponse]:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/issues/create
    Creates a new issue for the project specified with the id
    """

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    if request.POST.get("title"):
        url = (
            "/project/"
            + glProject["remoteProject"].path
            + "/"
            + str(glProject["remoteProject"].remoteIdentifier)
            + "/issues/"
        )
        try:
            repService = getRepositoryService(glProject["localProject"])
            repService.createIssue(
                glProject["localProject"],
                glProject["remoteInstance"],
                request.POST["title"],
                request.POST["description"],
                request.POST["milestone"],
                request.POST["label"],
            )

            # ToDo: not needed anymore?
            # if  settings.SEND_MAIL:
            #     repService = getRepositoryService(glProject['localProject'])
            #     milestone = repService.loadMilestones(glProject['localProject'], glProject['remoteInstance'],request.POST['milestone'])
            #     subjecttext = 'Hello, there is a new ticket in {}'.format(glProject['localProject'].name)
            #     messagetext = f'Title : {request.POST["title"]}\nLabel : {request.POST["label"]}\nMilestone : {milestone.title}\nDescription : {request.POST["description"]}'
            #    send mail if ticket is saved
            #    ## sendingEmail([glProject['localProject'].firstEMailAddress],messagetext,subjecttext)
        except:
            return redirect(url + "?error=invalid")

        return redirect(url)

    return HttpResponse(template("issue/create").render(glProject, request))


@login_required
def issue(request: WSGIRequest, slug: str, id: int, issue: int) -> HttpResponse:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/issues/<int:issue>
    Get the information needed to display a single issue specified with the id and the issue (issue id)
    """

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    if request.POST.get("comment"):
        try:
            repService = getRepositoryService(glProject["localProject"])
            body = (
                "**"
                + request.user.first_name
                + " "
                + request.user.last_name
                + ":**\n "
                + request.POST["comment"]
            )
            repService.createIssueComment(
                glProject["localProject"], glProject["remoteInstance"], issue, body
            )
        except:
            return redirect(
                "/project/"
                + glProject["remoteProject"].path
                + "/"
                + str(glProject["remoteProject"].id)
                + "/issues/"
                + str(issue)
                + "?error=invalid"
            )

    repService = getRepositoryService(glProject["localProject"])
    glProject["issue"] = repService.loadIssues(
        glProject["localProject"], glProject["remoteInstance"], iid=issue
    )

    return HttpResponse(template("issue/view").render(glProject, request))


@login_required
def milestones(request: WSGIRequest, slug: str, id: int) -> HttpResponse:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/milestones
    Get the information needed to display the milestones of the project specified with the id
    """

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    if not glProject["localProject"].enable_documentation:
        return redirect("/")

    return HttpResponse(template("milestone/list").render(glProject, request))


@login_required
def milestoneBoard(request: WSGIRequest, slug: str, id: int, mid: int) -> HttpResponse:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/milestone/<int:mid>
    Get the information needed to display a board of issues in this milestone
    """
    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    if not glProject["localProject"].enable_milestones:
        return redirect("/")

    repService = getRepositoryService(glProject["localProject"])
    # Todo
    milestone = repService.loadMilestones(
        glProject["localProject"], glProject["remoteInstance"], mid
    )
    milestoneIssues = repService.loadIssues(
        glProject["localProject"], glProject["remoteInstance"], milestone=mid
    )
    issues = {
        "open": [],
        "assigned": [],
        "closed": [],
        "timeEstimated": 0,
        "timeSpent": 0,
    }
    for issue in milestoneIssues:
        if issue.state == "closed":
            issues["closed"].append(issue)
        elif len(issue.assignees) > 0:
            issues["assigned"].append(issue)
        else:
            issues["open"].append(issue)

        issues["timeEstimated"] += issue.time_stats_time_estimate
        issues["timeSpent"] += issue.time_stats_total_time_spent

    issues["totalTime"] = issues["timeEstimated"] + issues["timeSpent"]

    return HttpResponse(
        template("milestone/board").render(
            glProject
            | {
                "issues": issues,
                "milestone": milestone,
                "total": len(issues["open"])
                + len(issues["assigned"])
                + len(issues["closed"]),
            },
            request,
        )
    )


@login_required
def fileList(request: WSGIRequest, slug: str, id: int) -> HttpResponse:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/download
    Get the information needed to display the files of the project specified with the id
    """

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    if not glProject["localProject"].enable_documentation:
        return redirect("/")

    return HttpResponse(
        template("file/list").render(
            glProject | {"fileTypes": DownloadableFile}, request
        )
    )


def fileDownload(request: WSGIRequest, slug: str, id: int, file: str) -> HttpResponse:
    """
    Given a file name from the uploads folder, download the file
    """

    assignment = (
        UserProjectAssignment.objects.filter(
            project__project_identifier=id, project__closed=False
        )
        .exclude(
            project__publicOverviewPassword__isnull=True,
            project__publicOverviewPassword__in=["", " ", None],
        )
        .first()
    )

    # glProject = loadProject(assignment.project, assignment.access_token)
    repService = getRepositoryService(assignment.project)
    glProject = repService.loadProject(assignment.project, assignment.access_token)

    # Only bxpass the regular permission system if the project is public and the user has already authenticated himself with the public board password
    if (
        not request.session.get("password")
        or not assignment.project.public_overview_password
        or request.session.get("password")
        != assignment.project.public_overview_password
    ):
        glProject = get_project(request, id)
        if isinstance(glProject, HttpResponse):
            return glProject

    if not os.path.exists(settings.MEDIA_ROOT + file) or not glProject:
        raise Http404

    return FileResponse(open(settings.MEDIA_ROOT + file, "rb"), as_attachment=True)


@login_required
def wiki(
    request: WSGIRequest, slug: str, id: int
) -> Union[HttpResponseRedirect, HttpResponse]:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/documentation
    Get the information needed to display an overview of the documentation pages of the project specified with the id
    Redirect to / if the documentation is disabled for the project
    """
    ### ToDo

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    if not glProject["localProject"].enable_documentation:
        return redirect("/")

    return HttpResponse(template("wiki/overview").render(glProject, request))


@login_required
def wikiPage(
    request: WSGIRequest, slug: str, id: int, page
) -> Union[HttpResponseRedirect, HttpResponse]:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/documentation/<path:page>
    Get the information needed to display a single documentation page of the project specified with the id
    Redirect to / if the documentation is disabled for the project
    """

    ### ToDo

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    if not glProject["localProject"].enable_documentation:
        return redirect("/")

    repService = getRepositoryService(glProject)
    glProject["page"] = repService.loadWikiPage(
        glProject["localProject"], glProject["remoteProject"], page
    )

    return HttpResponse(template("wiki/page").render(glProject, request))


@login_required
def printWiki(
    request: WSGIRequest, slug: str, id: int
) -> Union[HttpResponseRedirect, HttpResponse]:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/documentation/print
    Renders a pdf of the documentation pages to enable downloading them
    Redirect to / if the documentation is disabled for the project
    """

    glProject = get_project(request, id)
    if isinstance(glProject, HttpResponse):
        return glProject

    project_identifier = glProject["localProject"].project_identifier
    if not glProject["localProject"].enable_documentation:
        return redirect("/")

    pdfkit.from_string(
        template("print/wiki").render(glProject, request),
        "/tmp/" + project_identifier + ".pdf",
        {
            "encoding": "UTF-8",
            "--footer-center": "[page] " + _("of") + " [topage]",
            "--footer-left": settings.INTERFACE_NAME,
            "--footer-right": datetime.datetime.now().strftime("%d.%m.%Y"),
        },
        verbose=True,
    )

    with open("/tmp/" + project_identifier + ".pdf", "rb") as f:
        file_data = f.read()

    os.remove("/tmp/" + project_identifier + ".pdf")

    response = HttpResponse(file_data, content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="documentation.pdf"'

    return response


@login_required
def print_overview(request: WSGIRequest, slug: str, id: int) -> HttpResponse:
    """
    Handles the requests for /project/<slug:slug>/<int:id>/print/<str:date>
    Renders a PDF of the project overview to enable downloading it.
    """
    try:
        gl_project = get_project(request, id)
        if isinstance(gl_project, HttpResponse):
            return gl_project

        project_identifier = gl_project["localProject"].project_identifier
        repository_service = getRepositoryService(gl_project["localProject"])
        issues = repository_service.loadIssues(
            gl_project["localProject"], gl_project["remoteInstance"]
        )  # TODO: Check for different pages

        start_date = parse_date(request.GET.get("start"))
        end_date = parse_date(request.GET.get("end")) + datetime.timedelta(days=1)

        rendered_html = render_template(
            "print/overview", gl_project, issues, start_date, end_date, request
        )
        output_path = f"/tmp/{project_identifier}.pdf"
        pdf_options = {
            "encoding": "UTF-8",
            "--footer-center": f"[page] {_('of')} [topage]",
            "--footer-left": settings.INTERFACE_NAME,
            "--footer-right": datetime.datetime.now().strftime("%d.%m.%Y"),
        }

        pdfkit.from_string(rendered_html, output_path, pdf_options, verbose=True)

        with open(output_path, "rb") as file:
            file_data = file.read()

        os.remove(output_path)

        response = HttpResponse(file_data, content_type="application/pdf")
        response["Content-Disposition"] = 'attachment; filename="overview.pdf"'

        return response

    except Exception as e:
        # Basic error handling
        return HttpResponse(f"An error occurred: {e}", status=500)


def render_template(
    template_name: str,
    gl_project: Dict[str, Any],
    issues: Any,
    start_date: datetime.datetime,
    end_date: datetime.datetime,
    request: WSGIRequest,
) -> str:
    """
    Render the template with the given data.

    Args:
        template_name (str): The name of the template to render.
        gl_project (Dict[str, Any]): The project data.
        issues (Any): The issues data.
        start_date (datetime.datetime): The start date.
        end_date (datetime.datetime): The end date.
        request (WSGIRequest): The HTTP request object.

    Returns:
        str: The rendered HTML string.
    """
    template = get_template(template_name)
    context = {
        **gl_project,
        "issues": issues,
        "start": start_date,
        "end": end_date,
    }
    return template.render(context, request)


#
# Caching helpers
#


@login_required
@staff_member_required
def clearCache(request: WSGIRequest) -> HttpResponseRedirect:
    """
    Handles the requests for /cache/clear
    Resets the whole cache and redirects to /
    """

    cache.clear()

    redirectUrl = request.GET.get("redirect")
    if url_has_allowed_host_and_scheme(redirectUrl, None):
        return redirect(iri_to_uri(redirectUrl))
    return redirect("/")


@login_required
@staff_member_required
def warmupCache(request: WSGIRequest) -> HttpResponseRedirect:
    """
    Handles the requests for /cache/warmup
    Loads every project (from gitlab) and redirects to /
    """

    for project in Project.objects.all().prefetch_related("userprojectassignment_set"):
        if len(project.userprojectassignment_set.all()) > 0:
            # .first() will break the prefetch
            repService = getRepositoryService(project)
            repService.loadProject(
                project, project.userprojectassignment_set.all()[0].access_token
            )

    redirectUrl = request.GET.get("redirect")
    if url_has_allowed_host_and_scheme(redirectUrl, None):
        return redirect(iri_to_uri(redirectUrl))
    return redirect("/")


from main.githubService import GitHubService
from django.shortcuts import render


@login_required
def github_repos(request):
    github_service = GitHubService(token="your_github_token")
    repos = github_service.get_user_repos(username="your_github_username")
    return render(request, "github_repos.html", {"repos": repos})


@login_required
def github_issues(request, repo):
    github_service = GitHubService(token="your_github_token")
    repo = "SD-Twayn"
    issues = github_service.get_repo_issues(repo=repo)
    return render(request, "github_issues.html", {"issues": issues})


import base64
from datetime import datetime
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from django.http import HttpRequest, HttpResponse, FileResponse, Http404
from django.shortcuts import render
import requests


def decrypt_secret(secret: str, key: str) -> str:
    ciphering = "AES--CTR"
    encryption_iv = b"EinzigWahrerLoki"
    key = (key + "MerlinDerMagier").encode("utf-8")
    cipher = Cipher(
        algorithms.AES(key), modes.CTR(encryption_iv), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(base64.b64decode(secret)) + decryptor.finalize()
    return decrypted.decode("utf-8")[:8]


def get_sevdesk_auth() -> str:
    return settings.SEVDESK_TOKEN


def make_sevdesk_request(url: str, auth: str) -> Dict[str, Any]:
    headers = {"Authorization": auth, "Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


def angebote(request: HttpRequest) -> HttpResponse:
    secret = request.GET.get("secret")
    key1 = request.GET.get("key1")
    download = request.GET.get("download")

    if not secret or not key1:
        context = {
            "error_message": "Link ungültig",
            "title": "Error",
            "description": "",
            "noindex": True,
        }
        return render(request, "sd/angebote.html", context)

    id = decrypt_secret(secret, key1)
    sevdesk_auth = get_sevdesk_auth()

    order_url = f"https://my.sevdesk.de/api/v1/Order/{id}?embed=contact"
    order_result = make_sevdesk_request(order_url, sevdesk_auth)["objects"][0]

    position_url = f"https://my.sevdesk.de/api/v1/Order/{id}/getPositions?embed=unity"
    position_result = make_sevdesk_request(position_url, sevdesk_auth)["objects"]

    if download:
        pdf_url = f"https://my.sevdesk.de/api/v1/Order/{id}/getPdf"
        pdf_result = make_sevdesk_request(pdf_url, sevdesk_auth)["objects"]
        pdf_content = base64.b64decode(pdf_result["content"])
        response = HttpResponse(pdf_content, content_type=pdf_result["mimetype"])
        response["Content-Disposition"] = (
            f'attachment; filename="{pdf_result["filename"]}"'
        )
        return response

    context = {
        "order_result": order_result,
        "position_result": position_result,
        "title": order_result["header"],
        "description": "",
        "noindex": True,
    }

    return render(request, "angebote.html", context)
