import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Union

import requests
from django.conf import settings
from django.core.cache import cache
from django.utils.translation import gettext as _
from userinterface.models import Project
from userinterface.templatetags.dates import parse_date
from userinterface.tools.repositoryServiceInterface import (
    RepositoryServiceInterface,
    remoteStdIssue,
    remoteStdMergeRequest,
    remoteStdMilestone,
    remoteStdNote,
    remoteStdProject,
    remoteStdUser,
)
from .timetrackingHelper import calculateTime
from .wikiParser import parseStructure

logger = logging.getLogger(__name__)


class githubServiceCache(RepositoryServiceInterface):
    def loadProject(self, projectObject: Project, access_token: str) -> Dict[str, Any]:
        """
        Loads the project from GitHub and all its information and returns them.

        @return:
            dict:
                Either { 'remoteProject': GitHubProjectObject, 'localProject': Project, 'allMilestones': list or False, 'mostRecentIssues': list[:5], 'wikiPages': list or False, 'projectLabels': list, 'projectReleases': list, 'lastUpdated': datetime }
                or { 'localProject': { 'name': 'projectName' }, 'error': 'An error occurred: SomeException' }
        """
        cache_id = f"glh_{projectObject.project_identifier}"
        project = cache.get(cache_id)

        if not project:
            try:
                gh_project = self._fetch_github_project(
                    projectObject.project_identifier, access_token
                )
            except Exception as e:
                return {
                    "localProject": {"name": projectObject.name},
                    "error": _("An error occurred") + ": " + str(e),
                }

            project = {
                "remoteProject": self.loadRemoteProject(projectObject, gh_project),
                "remoteInstance": gh_project,
                "localProject": projectObject,
                "allMilestones": self.loadMilestones(projectObject, access_token),
                "mostRecentIssues": self.loadIssues(projectObject, access_token)[:5],
                "wikiPages": [],  # parseStructure(loadWikiPage(projectObject, ghProject)),
                "projectLabels": self.loadLabels(projectObject, access_token),
                "projectReleases": self.loadReleases(projectObject, access_token),
                "lastUpdated": self.lastUpdate(projectObject, access_token),
            }
            now = datetime.now()
            project["activeMilestones"] = [
                m
                for m in project["allMilestones"]
                if not m.expired
                and m.state == "active"
                and m.start_date != "?"
                and m.start_date < now
                and m.due_date != "?"
                and m.due_date >= now
            ]
            cache.set(cache_id, project, settings.CACHE_PROJECTS)

        return project

    def _fetch_github_project(
        self, project_identifier: str, token: str
    ) -> Dict[str, Any]:
        url = f"https://api.github.com/repos/{project_identifier}"
        headers = {"Authorization": f"token {token}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def loadRemoteProject(
        self, projectObject: Project, gh_project: Dict[str, Any]
    ) -> Dict[str, Any]:
        remote_project = remoteStdProject()
        remote_project.id = gh_project["id"]
        remote_project.remoteIdentifier = gh_project["id"]
        remote_project.path = "GitHub"
        remote_project.avatar_url = ""
        remote_project.description = gh_project["description"]
        remote_project.web_url = gh_project["html_url"]
        return remote_project

    def loadLabels(self, projectObject: Project, token: str) -> List[Dict[str, Any]]:
        """
        Loads the labels from GitHub for the given project object.

        @return:
            list: A list containing label objects.
        """
        cache_id = f"glh_{projectObject.project_identifier}_labels"
        labels = cache.get(cache_id)

        if not labels:
            url = f"https://api.github.com/repos/{projectObject.project_identifier}/labels"
            headers = {"Authorization": f"token {token}"}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            labels = response.json()
            cache.set(cache_id, labels, settings.CACHE_PROJECTS)

        return labels

    def loadReleases(self, projectObject: Project, token: str) -> List[Dict[str, Any]]:
        """
        Loads the releases from GitHub for the given project object.

        @return:
            list: A list containing release objects.
        """
        cache_id = f"glh_{projectObject.project_identifier}_releases"
        releases = cache.get(cache_id)

        if not releases:
            url = f"https://api.github.com/repos/{projectObject.project_identifier}/releases"
            headers = {"Authorization": f"token {token}"}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            releases = response.json()
            cache.set(cache_id, releases, settings.CACHE_PROJECTS)

        return releases

    def loadMilestones(
        self, projectObject: Project, token: str, iid: int = None
    ) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Loads the milestones from GitHub for the given project object.

        @return:
            list or dict: A list containing milestone objects or a single milestone object.
        """
        if not projectObject.enable_milestones:
            return []

        cache_id = f"glh_{projectObject.project_identifier}_milestones"
        if iid:
            cache_id = f"{cache_id}_{str(iid)}"

        milestones = cache.get(cache_id)
        if not milestones:
            url = f"https://api.github.com/repos/{projectObject.project_identifier}/milestones"
            headers = {"Authorization": f"token {token}"}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            milestones = response.json()
            cache.set(cache_id, milestones, settings.CACHE_MILESTONES)

        return milestones

    def loadIssues(
        self,
        projectObject: Project,
        token: str,
        iid: int = None,
        page: int = 1,
        milestone: int = None,
        label: str = None,
        status: str = None,
    ) -> Union[List[Dict[str, Any]], Dict[str, Any], None]:
        """
        Loads issues from GitHub and returns them.

        @return:
            list or dict or None: Either a list of issues, a single issue with details, or None if an error occurs.
        """
        logger.debug("Starting loadIssues function")
        logger.debug(
            f"Parameters: iid={iid}, page={page}, milestone={milestone}, label={label}, status={status}"
        )

        if status == "opened":
            status = "open"
        elif status == "closed":
            status = "closed"

        if isinstance(label, str):
            label = [label]

        cache_id = self._generate_cache_id(
            projectObject.project_identifier, iid, milestone, label, status, page
        )
        logger.debug(f"Cache ID: {cache_id}")

        issues = cache.get(cache_id)
        if not issues:
            try:
                if iid:
                    logger.debug(f"Fetching issue with ID: {iid}")
                    issues = self._fetch_issue_by_id(
                        projectObject.project_identifier, iid, token
                    )
                else:
                    logger.debug("Fetching issues with filters")
                    issues = self._fetch_issues(
                        projectObject.project_identifier,
                        milestone,
                        label,
                        status,
                        page,
                        token,
                    )
                cache.set(cache_id, issues, settings.CACHE_ISSUES)
                logger.debug("Issues fetched and cached successfully")
            except Exception as e:
                logger.error(f"An error occurred: {e}")
                return {"error": _("An error occurred") + ": " + str(e)}

        return issues

    def _generate_cache_id(
        self,
        project_identifier: str,
        iid: int = None,
        milestone: int = None,
        label: List[str] = None,
        status: str = None,
        page: int = 1,
    ) -> str:
        """
        Generates a cache ID based on the provided parameters.

        @return:
            str: The generated cache ID.
        """
        cache_id = f"glh_{project_identifier}_issues"
        if iid:
            cache_id = f"{cache_id}_{str(iid)}"
        elif milestone:
            cache_id = f"{cache_id}_m{str(milestone)}"
        elif label and status:
            cache_id = f"{cache_id}_ls{str(status)}_{str(label)}"
        elif label:
            cache_id = f"{cache_id}_l{str(label)}"
        elif status:
            cache_id = f"{cache_id}_s{str(status)}"
        return f"{cache_id}_p{str(page)}"

    def _fetch_issue_by_id(
        self, project_identifier: str, iid: int, token: str
    ) -> Dict[str, Any]:
        """
        Fetches a single issue by ID from GitHub.

        @return:
            dict: A dictionary containing issue details.
        """
        url = f"https://api.github.com/repos/{project_identifier}/issues/{iid}"
        headers = {"Authorization": f"token {token}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        issue = response.json()
        return self._get_issue_details(issue, token)

    def _fetch_issues(self, project_identifier, milestone, label, status, page, token):
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        url = f"https://api.github.com/repos/{project_identifier}/issues"
        params = {
            "milestone": milestone,
            "labels": label,
            "state": status,
            "page": page,
            "per_page": 30,
        }
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # This will raise an HTTPError for bad responses
        return response.json()

    def _get_issue_details(self, token, issue: Dict[str, Any]) -> Dict[str, Any]:
        """
        Converts a GitHub issue to a detailed issue dictionary.

        @return:
            dict: A dictionary containing issue details.
        """
        logger.debug("Starting _get_issue_details function")
        issue_details = self.convertIssue(issue)
        comments_url = issue["comments_url"]
        headers = {"Authorization": f"token {token}"}
        response = requests.get(comments_url, headers=headers)
        response.raise_for_status()
        comments = response.json()
        notes = [self.convertNote(comment) for comment in comments]
        for note in notes:
            issue_details = calculateTime(issue_details, note["body"])
        issue_details["notes"] = notes
        return issue_details

    def convertIssue(self, remoteIssue: Dict[str, Any]) -> Dict[str, Any]:
        newIssue = remoteStdIssue()
        newIssue.id = remoteIssue["id"]
        newIssue.iid = remoteIssue["number"]
        newIssue.remoteIdentifier = remoteIssue["number"]
        newIssue.confidential = False
        newIssue.state = remoteIssue["state"]
        newIssue.isOpen = newIssue.state == "open"
        newIssue.title = remoteIssue["title"]
        newIssue.description = remoteIssue["body"]
        newIssue.created_at = remoteIssue["created_at"]
        newIssue.updated_at = remoteIssue["updated_at"]
        newIssue.due_date = None
        newIssue.closed_at = remoteIssue["closed_at"]
        newIssue.web_url = remoteIssue["url"]
        newIssue.user_notes_count = remoteIssue["comments"]
        newIssue.author = self.convertUser(remoteIssue["user"])

        if remoteIssue.get("assignees"):
            newIssue.assignees = [
                self.convertUser(assignee) for assignee in remoteIssue["assignees"]
            ]

        if remoteIssue.get("milestone"):
            newIssue.milestone = self.convertMilestone(remoteIssue["milestone"])

        if remoteIssue.get("labels"):
            newIssue.labels = [label["name"] for label in remoteIssue["labels"]]
            if any(
                label
                in [
                    "confidential",
                    "Confidential",
                    "hidden",
                    "Hidden",
                    "internal",
                    "Internal",
                ]
                for label in newIssue.labels
            ):
                newIssue.confidential = True

        return newIssue

    def convertUser(self, remoteUser: Dict[str, Any]) -> Dict[str, Any]:
        newUser = remoteStdUser()
        newUser.id = remoteUser["id"]
        newUser.state = ""
        newUser.username = remoteUser["login"]
        newUser.name = remoteUser["login"]
        newUser.web_url = remoteUser["html_url"]
        return newUser

    def convertMilestone(
        self,
        remoteMilestone: Dict[str, Any],
        startDate: datetime = datetime(2020, 1, 1, 0, 0),
    ) -> Dict[str, Any]:
        newMilestone = remoteStdMilestone()
        newMilestone.id = remoteMilestone["id"]
        newMilestone.remoteIdentifier = remoteMilestone["number"]
        newMilestone.title = remoteMilestone["title"]
        newMilestone.description = remoteMilestone["description"]
        newMilestone.state = remoteMilestone["state"]
        newMilestone.isActive = newMilestone.state == "open"
        newMilestone.expired = (
            (
                datetime.now()
                - datetime.strptime(remoteMilestone["due_on"], "%Y-%m-%dT%H:%M:%SZ")
            ).days
            > 0
            if remoteMilestone["due_on"]
            else False
        )
        newMilestone.start_date = startDate
        newMilestone.due_date = (
            datetime.strptime(remoteMilestone["due_on"], "%Y-%m-%dT%H:%M:%SZ")
            if remoteMilestone["due_on"]
            else None
        )
        newMilestone.web_url = remoteMilestone["url"]
        return newMilestone

    def convertMergeRequest(self, remoteMergeRequest: Dict[str, Any]) -> Dict[str, Any]:
        newMergeRequest = remoteStdMergeRequest()
        newMergeRequest.id = remoteMergeRequest["id"]
        newMergeRequest.iid = remoteMergeRequest["number"]
        newMergeRequest.remoteIdentifier = remoteMergeRequest["number"]
        newMergeRequest.title = remoteMergeRequest["title"]
        newMergeRequest.description = remoteMergeRequest["body"]
        newMergeRequest.state = remoteMergeRequest["state"]
        newMergeRequest.created_at = remoteMergeRequest["created_at"]
        newMergeRequest.updated_at = remoteMergeRequest["updated_at"]
        newMergeRequest.user_notes_count = remoteMergeRequest["comments"]
        newMergeRequest.draft = remoteMergeRequest["draft"]
        newMergeRequest.changes_count = remoteMergeRequest["commits"]
        newMergeRequest.web_url = remoteMergeRequest["html_url"]
        return newMergeRequest

    def convertNote(self, remoteNote: Dict[str, Any]) -> Dict[str, Any]:
        newNote = remoteStdNote()
        newNote.id = remoteNote["id"]
        newNote.body = remoteNote["body"]
        newNote.created_at = remoteNote["created_at"]
        newNote.updated_at = remoteNote["updated_at"]
        newNote.confidential = False
        newNote.internal = False
        newNote.author = self.convertUser(remoteNote["user"])
        return newNote

    def lastUpdate(self, projectObject: Project, token: str) -> datetime:
        def get_naive_datetime(dt: datetime) -> datetime:
            """Ensure the datetime is naive."""
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return dt

        project = self.getInstance(projectObject, token)
        last_update = project["updated_at"]
        if last_update < project["pushed_at"]:
            last_update = project["pushed_at"]

        url = f"https://api.github.com/repos/{projectObject.project_identifier}/issues"
        headers = {"Authorization": f"token {token}"}
        params = {
            "state": "all",
            "sort": "updated",
            "direction": "desc",
            "since": last_update,
        }
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        remote_issues = response.json()
        if remote_issues:
            last_update = remote_issues[0]["updated_at"]

        naive_last_update = get_naive_datetime(
            datetime.strptime(last_update, "%Y-%m-%dT%H:%M:%SZ")
        )
        return datetime.now(timezone.utc).astimezone().replace(tzinfo=None)

    def getInstance(self, projectObject: Project, token: str) -> Dict[str, Any]:
        """
        Get the GitHub repository object instance (remoteProject).

        @return:
            dict: The GitHub repository object.
        """
        url = f"https://api.github.com/repos/{projectObject.project_identifier}"
        headers = {"Authorization": f"token {token}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
