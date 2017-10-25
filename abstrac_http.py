class AbstractHttpRequest:

    def _init_(self):
        self.sender = None
        self.receiver = None
        self.page = None
        # array [key, file] of abstract params
        self.params = None
        self.cookies = None
        self.tag = None
        # integer representing the function to execute
        self.action = None
        # array [key, file] or just [key] depending on the
        # action to perform
        self.action_params = None
        self.response = None

        # concretization details
        self.url = None
        self.method = None
        self.get_params = None
        self.post_params = None
        self.cookies = None


class AbstractHttpResponse:
    def _init_(self):
        self.sender = None
        self.receiver = None
        self.page = None
        self.content = None
        self.cookies = None
        self.tag = None

