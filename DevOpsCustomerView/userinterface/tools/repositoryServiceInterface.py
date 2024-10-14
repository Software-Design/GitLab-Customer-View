import abc
from abc import abstractmethod
from typing import Union
from .timetrackingHelper import calculateTime
import re

from userinterface.models import Project


class RepositoryServiceInterface(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'loadProject') and
                callable(subclass.loadProject) or
                NotImplemented)

    @abstractmethod
    def loadProject(self, projectObject: Project, access_token: str) -> dict:
        """Load in the data set"""
        raise NotImplementedError

    def loadLabels(self, projectObject: Project, tokenOrInstance) -> list:
        """
        Loads the labels from gitlab for the given project object

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            list:
                A list containing ProjectLabel objects
                [ gitlab.v4.objects.labels.ProjectLabel, ... ]
        """
        raise NotImplementedError

    def loadReleases(self, projectObject: Project, tokenOrInstance) -> list:
        """
        Loads the releases from gitlab for the given project object

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            list:
                A list containing ProjectRelease objects
                [ gitlab.v4.objects.labels.ProjectRelease, ... ]
        """
        raise NotImplementedError

    @abstractmethod
    def loadMilestones(self, projectObject: Project, tokenOrInstance, iid: int = None) -> Union[list, dict]:
        """
        Loads the milestones from gitlab for the given project object

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            A list containing ProjectMilestone objects
            [ gitlab.v4.objects.milestones.ProjectMilestone, ... ]

        milestones need to have (gitlab as reference):
            due_date as date
            start_date as date
            expired (True after due_date) as bool
        """
        raise NotImplementedError

    def loadIssues(self, projectObject: Project, tokenOrInstance, iid: int = None, page: int = 1, milestone: int = None,
                   label: str = None, status: str = None) -> Union[list, dict, None]:
        """
        Loads an issue or the issues from gitlab for the given project object

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            Either a list containing ProjectIssue objects, an dict with the ProjectIssues or None
            [ gitlab.v4.objects.issues.ProjectIssue ... ] or { 'data': gitlab.v4.objects.issues.ProjectIssue, 'notes': [] } or None

            id (reference of milestone in api)
        """
        raise NotImplementedError

    # def loadWikiPage(self, projectObject: Project, tokenOrInstance, slug: str = None) -> Union[ProjectWiki, list]:
    #     """
    #     Loads a project wiki page or all wiki pages object from gitlab using the project identifier and slug
    #
    #     @params:
    #         tokenOrInstance:
    #             Is either a string (token) or a gitlab.v4.objects.projects.Project instance
    #
    #     @return:
    #         Either a single wiki page if slug is set or all pages of the project in a list
    #     """
    #     raise NotImplementedError

    def getInstance(self, projectObject: Project, tokenOrInstance):
        """
        Get the gitlab project object instance (remoteProject)

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            gitlab.v4.objects.projects.Project
        """
        raise NotImplementedError

class remoteStdProject:
    id = -1
    remoteIdentifier = ""
    path = ""
    avatar_url = ""
    description = ""
    web_url = ""
    updated_at = None

    # def __init__(self):
    # def __str__(self):

class remoteStdMilestone:
    id = -1
    remoteIdentifier = ""
    start_date = ""
    due_date = ""
    expired = ""
    state = ""
    isActive = True
    description = ""
    title = ""
    web_url = ""

    # def __init__(self):
    # def __str__(self):

class remoteStdMergeRequest:
    id = -1
    iid = -1
    remoteIdentifier = ""
    title = ""
    description = ""
    state = ""
    created_at = None
    updated_at = None
    user_notes_count = 0
    draft = True
    work_in_progress = True
    changes_count = 0
    web_url = ""

    # def __init__(self):
    # def __str__(self):

class remoteStdUser:
    id = -1
    state = ""
    username = ""
    name = ""
    web_url = ""

class remoteStdNote:
    id = -1
    body = ""
    author = remoteStdUser()
    created_at = None
    updated_at = None
    confidential = False
    internal = False
    system = False
    
    def cleanBody(self):
        self.body = self.body.replace('\\','')
        regex_pattern = r'\[(?P<kind>spend|spent|estimate|estimated) (?P<mode>add|subtract|set) (?P<duration>\d+[wdhmsWDHMS]*(?:\s*\d+[wdhmsWDHMS]*)*)(?P<text>.*)?\]'
        # find all matches of text group and replace the full match with it
        matches = re.finditer(regex_pattern, self.body.replace('\\',''))
        for match in matches:
                self.body = self.body.replace(match.group(0), match.group('text'))
            
        return re.sub(regex_pattern, '', self.body.replace('\\','')).strip()

class remoteStdIssue:
    id = -1
    iid = -1
    remoteIdentifier = ""
    confidential = True
    state = ""
    isOpen = True
    title = ""
    description = ""
    created_at = None
    updated_at = None
    due_date = None
    closed_at = None
    user_notes_count = 0
    web_url = ""
    invoice_notes = []

    author = remoteStdUser()

    assignees = []

    milestone = remoteStdMilestone()

    labels = []
    notes = []

    time_stats_human_time_estimate = 0
    time_stats_human_total_time_spent = 0
    time_stats_time_estimate = 0
    time_stats_total_time_spent = 0

    mergeRequests = remoteStdMergeRequest()

    # "time_stats": {
    #        "time_estimate": 0,
    #        "total_time_spent": 0,
    #        "human_time_estimate": null,
    #        "human_total_time_spent": null
    # }

    # "milestone": {
    #     "project_id": 1,
    #     "description": "Ducimus nam enim ex consequatur cumque ratione.",
    #     "state": "closed",
    #     "due_date": null,
    #     "iid": 2,
    #     "created_at": "2016-01-04T15:31:39.996Z",
    #     "title": "v4.0",
    #     "id": 17,
    #     "updated_at": "2016-01-04T15:31:39.996Z"
    # },

    # "labels": ["foo", "bar"],

    # def __init__(self):
    # def __str__(self):

    def getTimeDifference(self, kind, start, end):
        time = 0
        for comment in self.notes:
            if comment.created_at >= start and comment.created_at <= end:
                duration = calculateTime(None, comment.body)
                if kind == 'estimate':
                    time += duration[0]
                else:
                    time += duration[1]
        return time