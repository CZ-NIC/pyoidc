class SingleService:
    def __init__(self, host):
        self.host = host
        self.endpoints = {}  # type: ignore


class SingleClient:
    def __init__(self, host):
        self.host = host
        self.requests = {}  # type: ignore
