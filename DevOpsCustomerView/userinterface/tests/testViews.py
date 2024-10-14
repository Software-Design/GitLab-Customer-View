import pytest
from django.contrib.auth import login
from django.contrib.auth.models import AnonymousUser, User
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse, HttpResponseRedirect
from django.test import RequestFactory, TestCase
from django.urls import resolve
from django.urls.exceptions import Resolver404

from ..context_processors import settings
from ..models import Project, TeamMember, UserProjectAssignment
from ..tools.wikiParser import parseStructure
from ..views import clearCache, index, warmupCache
from ..tools.viewsHelper import get_project

# ===================================================================
#
# Test Helper
#
# ===================================================================


def fake_request(
    method: str = "get", path: str = "/", withAuthUser: bool = False, data: dict = {}
) -> WSGIRequest:
    """
    Uses the request factory to build a fake request object and returns it
    """

    factory = RequestFactory()
    request = getattr(factory, method, factory.get)(path, data)
    request.user = AnonymousUser()

    try:
        middleware = SessionMiddleware(resolve(path))
    except Resolver404:
        # ignore that the path is invalid
        print(f"invalid path detected: {path}")
        pass
    else:
        middleware.process_request(request)
        request.session.save()

    if withAuthUser:
        login(
            request, User.objects.get(username="Darth", is_staff=True, is_active=True)
        )

    return request


class DictObj:
    def __init__(self, in_dict: dict):
        for key, val in in_dict.items():
            if isinstance(val, (list, tuple)):
                setattr(
                    self, key, [DictObj(x) if isinstance(x, dict) else x for x in val]
                )
            else:
                setattr(self, key, DictObj(val) if isinstance(val, dict) else val)


# ===================================================================
#
#  The actual tests
#
# ===================================================================


class TestViews(TestCase):
    """
    Tests the view functions of the views.py
    """

    def setUp(self):
        """
        Sets up the database for the tests
        """

        self.user = User.objects.create(
            username="Darth", email="darth@vader.com", is_staff=True, is_active=True
        )
        self.user.set_password("test123")
        self.user.save()
        self.teammember = TeamMember.objects.create(
            name="Luke",
            email="luke@skywalker.com",
            phone="",
            homepage="",
            username="@skywalker",
        )
        self.project = Project.objects.create(
            project_identifier=12345,
            name="New Death Star",
            firstEMailAddress="luke@skywalker.de",
        )
        self.projectassignment = UserProjectAssignment.objects.create(
            project=self.project, user=self.user
        )

    def test_cacheViews(self):
        """
        Testing the views related to the cache (clear and warmup the cache)
        """

        cache.set("bestSaga", "starwars")
        clearCache(fake_request("get", "/cache/clear/"))
        assert cache.get("bestSaga", None) == "starwars"

        warmupCache(fake_request("get", "/cache/warmup/"))
        clearCache(fake_request("get", "/cache/clear/", True))
        assert cache.get("bestSaga", None) == None

    def test_tools_wikiParser(self):
        """
        Testing the wiki parser
        """

        structure = parseStructure(
            [
                DictObj(
                    {
                        "content": "We assume that X-Wings cannot have any damage on our giant death star. Nothing to worry about.",
                        "format": "markdown",
                        "slug": "x-wing",
                        "title": "X-Wings - a risk for our death star?",
                        "encoding": "UTF-8",
                    }
                )
            ]
        )

        assert structure["/"][0]["title"] == "X-Wings - a risk for our death star?"

    def test_get_project(self):

        anonymusGetRequest = fake_request(withAuthUser=True)
        try:
            get_project(anonymusGetRequest, 12345)
        except Exception as e:
            assert True
            return
        assert True == False

    def test_contextpreprocessors(self):
        """
        Testing the context processor
        """

        request = fake_request()
        context = settings(request)
        assert context["settings"].DEBUG == False

    def test_index(self):
        """
        Testing the index view
        """

        anonymusGetRequest = fake_request()
        authorizedGetRequest = fake_request("get", "/", True)

        # login attempts
        loginFailedPostRequest = fake_request(
            "post", data={"email": self.user.email, "password": "d5f4g5ds45"}
        )  # invalid
        loginSuccessPostRequest1 = fake_request(
            "post", data={"email": self.user.email, "password": "test123"}
        )  # valid with email
        loginSuccessPostRequest2 = fake_request(
            "post", data={"email": self.user.username, "password": "test123"}
        )  # valid with username

        anonymusGetResponse = index(anonymusGetRequest)
        authorizedGetResponse = index(authorizedGetRequest)

        loginFailedPostResponse = index(loginFailedPostRequest)
        loginSuccessPostResponse1 = index(loginSuccessPostRequest1)
        loginSuccessPostResponse2 = index(loginSuccessPostRequest2)

        for response in [anonymusGetResponse, authorizedGetResponse]:
            assert (
                type(response) == HttpResponse
                and response.status_code == 200
                or type(response) == HttpResponseRedirect
                and response.status_code == 302
            )

        for i, response in enumerate(
            [
                loginFailedPostResponse,
                loginSuccessPostResponse1,
                loginSuccessPostResponse2,
            ]
        ):
            if response.status_code != 302:
                print(response, i)  # debug
            assert (
                type(response) == HttpResponseRedirect and response.status_code == 302
            )

        assert loginFailedPostResponse.url == "/?error=invalid"
        assert loginSuccessPostResponse1.url == "/overview/"
        assert loginSuccessPostResponse2.url == "/overview/"
