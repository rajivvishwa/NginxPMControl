import requests
class BearerAuth(requests.auth.AuthBase):
    """Custom authentication class for Bearer tokens."""
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r