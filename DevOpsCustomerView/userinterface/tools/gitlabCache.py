from typing import Union

import gitlab
import re
from datetime import datetime, timezone
from django.conf import settings
from django.core.cache import cache
from django.utils.translation import gettext as _
from gitlab.v4.objects.wikis import ProjectWiki
from userinterface.templatetags.dates import parse_date, parse_iso
from userinterface.models import Project
from userinterface.templatetags.numbers import parseHumanizedTime, humanizeTime
from .timetrackingHelper import calculateTime
from .wikiParser import parseStructure

from userinterface.tools.repositoryServiceInterface import RepositoryServiceInterface, remoteStdProject, remoteStdMilestone, remoteStdIssue, remoteStdUser, remoteStdMergeRequest, remoteStdNote

class gitlabServiceCache(RepositoryServiceInterface):
    def loadProject(self, projectObject: Project, access_token: str) -> dict:
        """
        Loads the project from gitlab and all its information and returns them

        @return:
            dict:
                Either { 'remoteProject': GitLabProjectObject, 'localProject': Project, 'allMilestones': list or False, 'mostRecentIssues': list[:5], 'wikiPages': list or False, 'projectLabels':  }
                or { 'localProject': { 'name': 'projectName' }, 'error': 'An error occured: SomeException' }
        """

        id = f'glp_{projectObject.project_identifier}'

        project = cache.get(id)
        if not project:
            try:
                gl = gitlab.Gitlab(url=settings.GITLAB_URL, private_token=access_token)
                glProject = gl.projects.get(projectObject.project_identifier)
            except Exception as e:
                return {
                    'localProject': {'name': projectObject.name},
                    'error': _('An error occurred') + ': ' + str(e)
                }

            project = {
                'remoteProject': self.loadRemoteProject(projectObject, glProject),
                'remoteInstance': glProject,
                'localProject': projectObject,
                'allMilestones': self.loadMilestones(projectObject, glProject),
                'mostRecentIssues': self.loadIssues(projectObject, glProject)[:5],
                'wikiPages': [], #parseStructure(loadWikiPage(projectObject, glProject)),
                'projectLabels': self.loadLabels(projectObject, glProject),
                'projectReleases': self.loadReleases(projectObject, glProject),
                'lastUpdate': self.lastUpdate(projectObject, glProject)
            }
            now = datetime.now()
            project['activeMilestones'] = [m for m in list(project['allMilestones']) if
                                           not m.expired and m.state == 'active' and
                                           m.start_date != '?' and m.start_date < now and
                                               m.due_date != '?' and m.due_date >= now]
            cache.set(id, project, settings.CACHE_PROJECTS)

        return project

    def loadRemoteProject(self, projectObject: Project, tokenOrInstance):
        project = self.getInstance(projectObject, tokenOrInstance)
        remoteProject = remoteStdProject()

        remoteProject.id = project.id
        remoteProject.remoteIdentifier = project.id
        remoteProject.path = project.path
        remoteProject.avatar_url = project.avatar_url
        remoteProject.description = project.description
        remoteProject.web_url = project.web_url

        return remoteProject


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

        project = self.getInstance(projectObject, tokenOrInstance)
        id = f'glp_{projectObject.project_identifier}_labels'

        labels = cache.get(id)
        if not labels:
            labels = []
            glLabels = project.labels.list()
            for label in glLabels:
                if not projectObject.label_prefix or label.name.startswith(projectObject.label_prefix):
                    labels.append(label)

            cache.set(id, labels, settings.CACHE_PROJECTS)

        return labels

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

        project = self.getInstance(projectObject, tokenOrInstance)
        id = f'glp_{projectObject.project_identifier}_releases'

        glReleases = []
        labels = cache.get(id)
        if not labels:
            glReleases = project.releases.list()

            cache.set(id, glReleases, settings.CACHE_PROJECTS)

        return glReleases

    def loadMilestones(self, projectObject: Project, tokenOrInstance, iid: int = None) -> Union[list, dict]:
        """
        Loads the milestones from gitlab for the given project object

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            A list containing ProjectMilestone objects
            [ gitlab.v4.objects.milestones.ProjectMilestone, ... ]
        """

        if not projectObject.enable_milestones:
            return []

        project = self.getInstance(projectObject, tokenOrInstance)
        id = 'glp_' + projectObject.project_identifier + '_milestones'
        if iid:
            id = f'{id}_{str(iid)}'

        milestones = cache.get(id)
        if not milestones:
            milestones = []
            if iid:
                remoteMilestone = project.milestones.get(iid)
                newMilestone = self.convertMilestone(remoteMilestone)
                milestones = newMilestone
            else:
                remoteMilestones = project.milestones.list(order_by='start_date')
                for remoteMilestone in remoteMilestones:
                    newMilestone = self.convertMilestone(remoteMilestone)
                    milestones.append(newMilestone)

                # sort milestones by start date reverse, due to the fact the the GitLab Api does not support sorting
                milestones = sorted(milestones, key=lambda m: m.start_date if m.start_date != '?' else datetime(2020, 1, 1, 0, 0), reverse=True)

            cache.set(id, milestones, settings.CACHE_MILESTONES)

        return milestones

    def convertMilestone(self, remoteMilestone):
        newMilestone = remoteStdMilestone()
        if (type(remoteMilestone) == dict):
            newMilestone.id = remoteMilestone['id']
            newMilestone.remoteIdentifier = remoteMilestone['id']
            newMilestone.title = remoteMilestone['title']
            newMilestone.description = remoteMilestone['description']
            newMilestone.state = remoteMilestone['state']
            newMilestone.isActive = newMilestone.state == 'active'
            newMilestone.expired = remoteMilestone['expired']
            newMilestone.start_date = parse_date(remoteMilestone['start_date'])
            newMilestone.due_date = parse_date(remoteMilestone['due_date'])
            newMilestone.web_url = remoteMilestone['web_url']
        else:
            newMilestone.id = remoteMilestone.id
            newMilestone.remoteIdentifier = remoteMilestone.id
            newMilestone.title = remoteMilestone.title
            newMilestone.description = remoteMilestone.description
            newMilestone.state = remoteMilestone.state
            newMilestone.isActive = newMilestone.state == 'active'
            newMilestone.expired = remoteMilestone.expired
            newMilestone.start_date = parse_date(remoteMilestone.start_date)
            newMilestone.due_date = parse_date(remoteMilestone.due_date)
            newMilestone.web_url = remoteMilestone.web_url

        return newMilestone

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
        """
        if status == 'opened':
            status = 'opened'
        elif status == 'closed':
            status = 'closed'

        project = self.getInstance(projectObject, tokenOrInstance)

        id = f'glp_{projectObject.project_identifier}_issues'
        if iid:
            id = f'{id}_{str(iid)}'
        elif milestone:
            id = f'{id}_m{str(milestone)}'
        elif label and status:
            id = f'{id}_ls{str(status)}_{str(label)}'
        elif label:
            id = f'{id}_l{str(label)}'
        elif status:
            id = f'{id}_s{str(status)}'
        id = f'{id}_p{str(page)}'

        issues = cache.get(id)
        if not issues:
            # ToDo correct ?
            issues = []
            remoteIssues = []
            if iid:
                remoteIssue = project.issues.get(iid)
                newIssue = self.convertIssue(remoteIssue)

                if newIssue.confidential == True:
                    issues = None
                else:
                    mergeRequests = []
                    for remoteMergeRequest in remoteIssue.related_merge_requests():
                        newMR = self.convertMergeRequest(remoteMergeRequest)
                        mergeRequests.append(newMR)

                    notes = []
                    for remoteNote in remoteIssue.notes.list(order_by='created_at', sort='asc', system=False, get_all=True):
                        newNote = self.convertNote(remoteNote)
                        newIssue = calculateTime(newIssue, newNote.body)
                        notes.append(newNote)

                    newIssue.notes = notes
                    issues = {
                        'data': newIssue,
                        'notes': notes,
                        'mergeRequests': mergeRequests
                    }
            elif milestone:
                remoteIssues = project.milestones.get(milestone).issues(confidential=False, order_by='updated_at', sort='desc') #, page=page)
            elif label and status:
                remoteIssues = project.issues.list(confidential=False, order_by='updated_at', sort='desc', page=page, labels=label, state=status)
            elif label:
                remoteIssues = project.issues.list(confidential=False, order_by='updated_at', sort='desc', page=page, labels=label)
            elif status:
                remoteIssues = project.issues.list(confidential=False, order_by='updated_at', sort='desc', page=page, state=status)
            else:
                remoteIssues = project.issues.list(confidential=False, order_by='updated_at', sort='desc', page=page)

            for remoteIssue in remoteIssues:
                newIssue = self.convertIssue(remoteIssue)

                notes = []
                for remoteNote in remoteIssue.notes.list(system=False, get_all=True):
                    newNote = self.convertNote(remoteNote)
                    newIssue = calculateTime(newIssue, newNote.body)
                    notes.append(newNote)
                
                newIssue.notes = notes
                issues.append(newIssue)

            cache.set(id, issues, settings.CACHE_ISSUES)

        return issues
    
    def convertIssue(self, remoteIssue):
        newIssue = remoteStdIssue()
        newIssue.id = remoteIssue.id
        newIssue.iid = remoteIssue.iid
        newIssue.remoteIdentifier = remoteIssue.iid
        newIssue.confidential = remoteIssue.confidential
        newIssue.state = remoteIssue.state
        newIssue.isOpen = newIssue.state == 'opened'
        newIssue.title = remoteIssue.title
        newIssue.description = remoteIssue.description
        newIssue.created_at = parse_iso(remoteIssue.created_at)
        newIssue.updated_at = parse_iso(remoteIssue.updated_at)
        newIssue.due_date = parse_date(remoteIssue.due_date)
        newIssue.closed_at = parse_iso(remoteIssue.closed_at)
        newIssue.user_notes_count = remoteIssue.user_notes_count
        newIssue.web_url = remoteIssue.web_url
        newIssue.author = self.convertUser(remoteIssue.author)

        if remoteIssue.assignees:
            newIssue.assignees = []
            for assignee in remoteIssue.assignees:
                newUser = remoteStdUser()
                newUser.id = assignee['id']
                newUser.state = assignee['state']
                newUser.username = assignee['username']
                newUser.name = assignee['name']
                newUser.web_url = assignee['web_url']
                newIssue.assignees.append(newUser)

        if remoteIssue.milestone:
            newIssue.milestone = self.convertMilestone(remoteIssue.milestone)

        if remoteIssue.labels:
            newIssue.labels = remoteIssue.labels
            
            if 'confidential' in newIssue.labels or 'Confidential' in newIssue.labels or 'hidden' in newIssue.labels or 'Hidden' in newIssue.labels or 'internal' in newIssue.labels or 'Internal' in newIssue.labels:
                newIssue.confidential = True

        return newIssue

    def convertUser(self, remoteUser):
        newUser = remoteStdUser()
        newUser.id = remoteUser['id']
        newUser.state = remoteUser['state']
        newUser.username = remoteUser['username']
        newUser.name = remoteUser['name']
        newUser.web_url = remoteUser['web_url']

        return newUser

    def convertMergeRequest(self, remoteMergeRequest):
        newMergeRequest = remoteStdMergeRequest()
        newMergeRequest.id = remoteMergeRequest['id']
        newMergeRequest.iid = remoteMergeRequest['iid']
        newMergeRequest.remoteIdentifier = remoteMergeRequest['iid']
        newMergeRequest.title = remoteMergeRequest['title']
        newMergeRequest.description = remoteMergeRequest['description']
        newMergeRequest.state = remoteMergeRequest['state']
        newMergeRequest.created_at = parse_iso(remoteMergeRequest['created_at'])
        newMergeRequest.updated_at = parse_iso(remoteMergeRequest['updated_at'])
        newMergeRequest.user_notes_count = remoteMergeRequest['user_notes_count']
        newMergeRequest.draft = remoteMergeRequest['draft']
        newMergeRequest.work_in_progress = remoteMergeRequest['work_in_progress']
        newMergeRequest.changes_count = int(remoteMergeRequest['changes_count'] if 'changes_count' in remoteMergeRequest and remoteMergeRequest['changes_count'] else 0)
        newMergeRequest.web_url = remoteMergeRequest['web_url']

        return newMergeRequest

    def convertNote(self, remoteNote):
        newNote = remoteStdNote()
        newNote.id = remoteNote.id
        newNote.body = remoteNote.body
        newNote.created_at = parse_iso(remoteNote.created_at)
        newNote.updated_at = parse_iso(remoteNote.updated_at)
        newNote.confidential = remoteNote.confidential
        newNote.system = remoteNote.system
        newNote.internal = remoteNote.internal
        newNote.author = self.convertUser(remoteNote.author)

        return newNote

    def loadWikiPage(self, projectObject: Project, tokenOrInstance, slug: str = None) -> Union[ProjectWiki, list]:
        """
        Loads a project wiki page or all wiki pages object from gitlab using the project identifier and slug

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            Either a single wiki page if slug is set or all pages of the project in a list
        """
        if not projectObject.enable_documentation:
            return False

        project = self.getInstance(projectObject, tokenOrInstance)
        if slug:
            id = 'glp_' + projectObject.project_identifier + '_' + slug
        else:
            id = 'glp_' + projectObject.project_identifier

        page = cache.get(id)
        if not page:
            if slug:
                if not projectObject.wikiPrefix or slug.startswith(projectObject.wikiPrefix):
                    page = project.wikis.get(slug)
            else:
                page = project.wikis.list()
            cache.set(id, page, settings.CACHE_PROJECTS)

        return page

    def createIssue(self, projectObject: Project, tokenOrInstance, title: str, description = '', milestoneIdentifier = '', labels = ''):
        project = self.getInstance(projectObject, tokenOrInstance)

        body = {'title': title, 'description': description}
        if labels != '':
            body['labels'] = labels
        if milestoneIdentifier != '':
            body['milestone_id'] = milestoneIdentifier

        issue = project.issues.create(body)
        cache.delete('glp_' + projectObject.project_identifier + '_issues_' + str(issue.iid))

        return True

    def createIssueComment(self, projectObject: Project, tokenOrInstance, issue: int, body: str):
        project = self.getInstance(projectObject, tokenOrInstance)

        project.issues.get(id=issue).notes.create({'body': body})

        id = 'glp_' + projectObject.project_identifier + '_issues_' + str(issue)
        cache.delete(id)

        return True

    def lastUpdate(self, projectObject: Project, tokenOrInstance):
        project = self.getInstance(projectObject, tokenOrInstance)
        lastUpdate = parse_iso(project.updated_at)
        import django
        return django.utils.timezone.make_aware(lastUpdate, timezone.utc)

    def getInstance(self, projectObject: Project, tokenOrInstance):
        """
        Get the gitlab project object instance (remoteProject)

        @params:
            tokenOrInstance:
                Is either a string (token) or a gitlab.v4.objects.projects.Project instance

        @return:
            gitlab.v4.objects.projects.Project
        """

        if type(tokenOrInstance) == str:
            gl = gitlab.Gitlab(url=settings.GITLAB_URL, private_token=tokenOrInstance)
            project = gl.projects.get(projectObject.project_identifier)
        else:
            project = tokenOrInstance

        return project