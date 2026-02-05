# anticsrfer
A Burpsuite suite plugin in Jython to bypass csrf protection that retrieves the token from another endpoint prior to the request

The plugin before sending a POST requst from your repeater or other tools in Burpsuite, sends a request to the token endpoint, and replaces the token in your actual POST request. The token is first fetched using the same cookies as the your request, and then is replaced in your request in the respective header. The plugin ignores POST requests in the Proxy tool unless a custom header is presenet (in order to use with other tools like sqlmap for example). Mutli-part POST requests are also ignored.
