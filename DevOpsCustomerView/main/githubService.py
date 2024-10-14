# DevOpsCustomerView/main/github_service.py
import requests

class GitHubService:
    def __init__(self, token):
        self.token = token
        self.base_url = "https://api.github.com"

    def get_headers(self):
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def get_user_repos(self, username):
        url = f"{self.base_url}/users/{username}/repos"
        response = requests.get(url, headers=self.get_headers())
        response.raise_for_status()
        return response.json()

    def get_repo_issues(self, repo):
        url = f"{self.base_url}/repos/SD-Software-Design-GmbH/{repo}/issues"
        response = requests.get(url, headers=self.get_headers())
        response.raise_for_status()
        return response.json()