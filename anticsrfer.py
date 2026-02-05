from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
from java.net import URL


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Per-Request AntiForgery Token Fetcher")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerHttpListener(self)
        self.stdout.println("[+] AntiForgery Token Extension loaded")

        self.token_path = "/Authorization/AntiForgeryToken"
        self.token_url = URL(
            "https",
            "10.10.10.10",
            4141,
            self.token_path
        )

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        request = messageInfo.getRequest()
        request_info = self.helpers.analyzeRequest(messageInfo)
        method = request_info.getMethod()
        url = request_info.getUrl()
        headers = list(request_info.getHeaders())

        # Skip Proxy traffic
        if toolFlag == self.callbacks.TOOL_PROXY:
            process_me = False

            for h in headers:
                if h.lower() == "x-process-me: true":
                    process_me = True
                    break

            if not process_me:
                return

        # Skip multipart form in case of uploads
        for h in headers:
            if h.lower().startswith("content-type:") and "multipart/form-data" in h.lower():
                return

        # Ignore token endpoint itself
        if url.getPath() == self.token_path:
            return

        if method.upper() != "POST":
            return

        try:
            #self.stdout.println("[*] POST detected - fetching anti-forgery token") ########## ENABLE FOR DEBUGGING

            # Build headers for GET
            get_headers = []

            # Correct request line
            get_headers.append(
                "GET {} HTTP/2".format(self.token_path)
            )

            # Correct Host header
            get_headers.append(
                "Host: {}:{}".format(
                    self.token_url.getHost(),
                    self.token_url.getPort()
                )
            )

            # Reuse cookies + auth-related headers only
            for h in headers:
                hl = h.lower()
                if (
                    hl.startswith("cookie:")
                    or hl.startswith("authorization:")
                    or hl.startswith("x-requested-with:")
                    or hl.startswith("referer:")
                ):
                    get_headers.append(h)

            # Build GET request (NO BODY)
            token_request = self.helpers.buildHttpMessage(get_headers, None)

            # This returns response BYTES, not IHttpRequestResponse
            response_bytes = self.callbacks.makeHttpRequest(
                self.token_url.getHost(),
                self.token_url.getPort(),
                True,
                token_request
            )

            if response_bytes is None:
                self.stderr.println("[-] No response from token endpoint")
                return

            response_info = self.helpers.analyzeResponse(response_bytes)
            body_offset = response_info.getBodyOffset()
            token = self.helpers.bytesToString(
                response_bytes[body_offset:]
            ).strip()

            if not token:
                self.stderr.println("[-] Empty token received")
                return

            #self.stdout.println("[+] Token fetched successfully") ########## ENABLE FOR DEBUGGING

            # Rebuild POST headers
            new_headers = []
            for h in headers:
                if not h.lower().startswith("x-request-verification-token"):
                    new_headers.append(h)

            new_headers.append(
                "X-Request-Verification-Token: {}".format(token)
            )

            body = request[request_info.getBodyOffset():]
            new_request = self.helpers.buildHttpMessage(new_headers, body)

            messageInfo.setRequest(new_request)
            #self.stdout.println("[+] POST updated with fresh token") ########## ENABLE FOR DEBUGGING

        except Exception as e:
            self.stderr.println("[-] Exception: {}".format(e))
