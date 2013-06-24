import httplib
import json
import logging
import re
import urlparse

from lib import oauth


class TwitterException(Exception):
  pass

class TwitterAuthError(TwitterException):
  pass

class TwitterHTTPError(TwitterException):
  pass

class TwitterValueError(TwitterException):
  pass

class TwitterOAuthClient(oauth.OAuthClient):
  """A collection of funcs to communicate with Twitter.

  In order to use the Twitter web API, a multi-step process
  is required to obtain an authenticated token, which is then
  used to cryptographically sign in each web request.

  To maintain the privacy of a consumer app's keys, web requests
  are signed externally then passed to funcs here as args.
  """

  def __init__(self):
    self.MAX_TWEET_LENGTH = 140

    self.REQUEST_TOKEN_URL = "http://api.twitter.com/oauth/request_token"
    self.ACCESS_TOKEN_URL = "http://api.twitter.com/oauth/access_token"
    self.AUTHORIZATION_URL = "http://api.twitter.com/oauth/authorize"
    self.VERIFY_CREDENTIALS_URL = "http://api.twitter.com/1.1/account/verify_credentials.json"

    self.HOME_TIMELINE_URL = "http://api.twitter.com/1.1/statuses/home_timeline.json"
    self.LOOKUP_USER_URL = "http://api.twitter.com/1.1/users/show.json"
    self.FOLLOW_USER_URL = "https://stream.twitter.com/1.1/statuses/filter.json"
    self.FOLLOW_SAMPLE_URL = "https://stream.twitter.com/1.1/statuses/sample.json"
    self.CONFIGURATION_URL = "http://api.twitter.com/1.1/help/configuration.json"
    self.SEND_TWEET_URL = "http://api.twitter.com/1.1/statuses/update.json"

    self.server_config = {"short_url_length":20,
                          "short_url_length_https":21}

  def get_connection(self, url, timeout=None):
    """Creates a connection object appropriate for a url.

    :returns: An HTTPConnection or HTTPSConnection.
    :raises: TwitterValueError
    """
    parts = urlparse.urlparse(url)
    conn = None
    if parts.scheme == 'http':
      conn = httplib.HTTPConnection(parts.netloc, timeout=timeout)
    elif parts.scheme == 'https':
      conn = httplib.HTTPSConnection(parts.netloc, timeout=timeout)
    else:
      raise TwitterValueError("Unknown scheme for url: %s" % url)
    return conn

  def fetch_request_token(self, oauth_request):
    """Gets a one-use request token during authentication. (via HTTP headers)
    Step 1.) fetch_request_token()
    Step 2.) authorize_token()
    Step 3.) fetch_access_token()

    :returns: An OAuthToken.
    :raises: TwitterAuthError, TwitterHTTPError
    """
    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request(oauth_request.http_method, self.REQUEST_TOKEN_URL, headers=oauth_request.to_header()) 
      response = conn.getresponse()
      body_str = response.read().rstrip('\r\n')
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Request token fetching failed. Reason: %s" % repr(err))
    if (response.status == 401):
      raise TwitterAuthError("Request token fetching failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))
    elif (response.status != 200):
      raise TwitterHTTPError("Request token fetching failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))

    try:
      return oauth.OAuthToken.from_string(body_str)
    except (KeyError) as err:
      raise TwitterAuthError("No request token received. Server response (%d %s): %s" % (response.status, response.reason, body_str))

  def fetch_access_token(self, oauth_request):
    """Gets a fully authenticated access token. (via HTTP headers)
    Step 1.) fetch_request_token()
    Step 2.) authorize_token()
    Step 3.) fetch_access_token()
    This request must've been made from consumer + req_token + verifier (PIN).

    :returns: An OAuthToken and a dict of user info (user_id/user_name).
    :raises: TwitterAuthError, TwitterHTTPError
    """
    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request(oauth_request.http_method, self.ACCESS_TOKEN_URL, headers=oauth_request.to_header()) 
      response = conn.getresponse()
      body_str = response.read().rstrip('\r\n')
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Access token fetching failed. Reason: %s" % repr(err))
    if (response.status == 401):
      raise TwitterAuthError("Access token fetching failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))
    elif (response.status != 200):
      raise TwitterHTTPError("Access token fetching failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))

    access_token = None
    src_user = None
    try:
      access_token = oauth.OAuthToken.from_string(body_str)

      params = urlparse.parse_qs(body_str, keep_blank_values=False)
      user_id = params["user_id"][0]
      user_name = params["screen_name"][0]
      src_user = {"user_id":user_id, "user_name":user_name}

    except (KeyError) as err:
      raise TwitterAuthError("Access token fetching failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))

    return (access_token, src_user)

  def get_authorization_url(self, req_token):
    """Gets the url for a user to visit in a browser to obtain a PIN.
    That PIN can then be passed to fetch_access_token().

    :returns: A url string.
    """
    return "%s?oauth_token=%s" % (self.AUTHORIZATION_URL, oauth.escape(req_token.key))

  def authorize_token(self, oauth_request):
    """Authorizes a request token. (via url query string)
    Step 1.) fetch_request_token()
    Step 2.) authorize_token()
    Step 3.) fetch_access_token()

    :returns: ???
    :raises: TwitterAuthError, TwitterHTTPError
    """
    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request(oauth_request.http_method, oauth_request.to_url()) 
      response = conn.getresponse()
      body_str = response.read().rstrip('\r\n')
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Token authorization failed. Reason: %s" % repr(err))
    if (response.status == 401):
      raise TwitterAuthError("Token authorization failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))
    elif (response.status != 200):
      raise TwitterHTTPError("Token authorization failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))

    return body_str

  def verify_credentials(self, oauth_request):
    """Gets info about the oauth access token's Twitter account.

    :returns: Two dicts of user info: (user_id/user_name) and (everything the server returned).
    :raises: TwitterAuthError, TwitterHTTPError, TwitterValueError
    """

    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request(oauth_request.http_method, oauth_request.to_url()) 
      response = conn.getresponse()
      body_str = response.read().rstrip('\r\n')
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Credentials verification failed. Reason: %s" % repr(err))
    if (response.status == 401):
      raise TwitterAuthError("Credentials verification failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))
    elif (response.status != 200):
      raise TwitterHTTPError("Credentials verification failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))

    user_info = None
    try:
      user_info = json.loads(body_str)
    except (ValueError) as err:
      raise TwitterValueError("Credentials verification failed. Unable to parse server response (%s): %s" % (repr(err), body_str))

    if ("id" in user_info and "screen_name" in user_info):
      basic_user_info = {"user_id":user_info["id"],"user_name":user_info["screen_name"]}
      return (basic_user_info, user_info)
    else:
      raise TwitterValueError("Credentials verification failed. No 'id' or 'screen_name' field in server response: %s" % body_str)

    return True

  def fetch_twitter_server_config(self):
    """Fetches the Twitter server's global settings.
    They will replace any previous values in "self.server_config".

    These settings rarely change, so call this no more than once
    per day on startup, and cache the result on disk. Calling this
    at all is optional. Hardcoded defaults should be sufficient.

    :param oauth_request: A GET request, with no parameters.
    :returns: A dict of settings.
    :raises: TwitterHTTPError, TwitterValueError
    """
    if (oauth_request.http_method != "GET"): raise TwitterHTTPError("fetch_twitter_server_config() requires a GET request.")

    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request(oauth_request.http_method, oauth_request.to_url())
      response = conn.getresponse()
      body_str = response.read().rstrip("\r\n")
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Twitter config fetching failed. Reason: %s" % repr(err))
    if (response.status != 200):
      raise TwitterHTTPError("Twitter config fetching failed. Server response (%d %s)." % (response.status, response.reason))

    new_config = None
    try:
      new_config = json.loads(body_str)
      self.server_config.clear()
      self.server_config.update(new_config)
    except (ValueError) as err:
      raise TwitterValueError("Twitter user lookup failed. Unable to parse server response (%s): %s" % (repr(err), body_str))

    return self.server_config

  def get_json_from_get_request(self, oauth_request, description="json"):
    """Gets a json-based object returned by Twitter after making an authenticated GET request.
    For use with: HOME_TIMELINE_URL.

    :param description: A phrase to describe this action when logging.
    :returns: Whatever the json response parses into.
    :raises: TwitterAuthError, TwitterHTTPError, TwitterValueError
    """
    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request(oauth_request.http_method, oauth_request.to_url())
      response = conn.getresponse()
      body_str = response.read().rstrip("\r\n")
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Twitter %s fetching failed. Reason: %s", (description, repr(err)))
    if (response.status != 200):
      raise TwitterHTTPError("Twitter %s fetching failed. Server response (%d %s)." % (description, response.status, response.reason))

    result = None
    try:
      result = json.loads(body_str)
      return result
    except (ValueError) as err:
      raise TwitterValueError("Twitter %s fetching failed. Unable to parse server response (%s): %s" % (description, repr(err), body_str))

  def get_sanitized_tweet(self, text, strip_urls=True):
    """Applies some regexes to clean up a tweet before sending.
    If you don't strip urls, you'll need to account for the t.co
    shortener when checking tweet length: urls will be up to a
    fixed size. See "self.server_config['short_url_length_https']".

    :param strip_urls: True to remove urls.
    :returns: The modified string.
    """
    text = re.sub("[\r]", "", text)  # \n is okay, \r is bad
    text = re.sub(" *https?://[^ ]+", "", text)
    text = re.sub("^ +", "", text)
    text = text.rstrip(" \n")
    return text

  def send_tweet(self, oauth_request):
    """Sends a tweet.
    When building the request, call get_sanitized_tweet() first.
    No need to encode the message text before calling this.
    The MAX_TWEET_LENGTH applies to the original text's UTF-8 char count, without encoding.

    :param oauth_request: A POST request, with 'status'=string parameter.
    :raises: TwitterAuthError, TwitterHTTPError, TwitterValueError
    """
    if (oauth_request.http_method != "POST"): raise TwitterHTTPError("send_tweet() requires a POST request.")

    text = oauth_request.get_parameter("status")
    if (len(text) == 0): return
    if (len(text) > self.MAX_TWEET_LENGTH): raise TwitterValueError("Tweet is too long (%d)." % len(text))

    headers = {'Content-Type' :'application/x-www-form-urlencoded'}

    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request('POST', oauth_request.http_url, body=oauth_request.to_postdata(), headers=headers)
      response = conn.getresponse()
      body_str = response.read().rstrip("\r\n")
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Tweet send failed. Reason: %s" % repr(err))
    if (response.status != 200):
      raise TwitterAuthError("Tweet send failed. Server response (%d %s): %s" % (response.status, response.reason, body_str))

    return

  def lookup_user(self, oauth_request):
    """Gets info about a Twitter account.

    :param oauth_request: A GET request, with 'screen_name'=string parameter.
    :returns: Two dicts of user info: (user_id/user_name) and (everything the server returned).
    :raises: TwitterAuthError, TwitterHTTPError, TwitterValueError
    """
    if (oauth_request.http_method != "GET"): raise TwitterHTTPError("lookup_user() requires a GET request.")

    conn = self.get_connection(oauth_request.http_url)
    response = None
    body_str = None
    try:
      conn.request(oauth_request.http_method, oauth_request.to_url())
      response = conn.getresponse()
      body_str = response.read().rstrip("\r\n")
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Twitter user lookup failed. Reason: %s" % repr(err))
    if (response.status != 200):
      raise TwitterHTTPError("Twitter user lookup failed. Server response (%d %s)." % (response.status, response.reason))

    user_info = None
    try:
      user_info = json.loads(body_str)
    except (ValueError) as err:
      raise TwitterValueError("Twitter user lookup failed. Unable to parse server response (%s): %s" % (repr(err), body_str))

    if ("id" in user_info and "screen_name" in user_info):
      basic_user_info = {"user_id":user_info["id"],"user_name":user_info["screen_name"]}
      return (basic_user_info, user_info)
    elif ("error" in user_info):
      raise TwitterValueError("Twitter user lookup failed. Server response: %s" % user_info["error"])
    else:
      raise TwitterValueError("Twitter user lookup failed. No 'id'/'screen_name' or 'error' fields in server response: %s" % body_str)

  def access_user_stream(self, oauth_request):
    """Opens an on-going connection to follow a Twitter user, and all related replies.

    :param oauth_request: A POST request, with 'follow'=userid and 'delimited'='length' parameters.
    :returns: An HTTPConnection and HTTPResponse, which should be read immediately.
    :raises: TwitterAuthError, TwitterHTTPError
    """
    if (oauth_request.http_method != "POST"): raise TwitterHTTPError("access_user_stream() requires a POST request.")
    headers = {'Content-Type' :'application/x-www-form-urlencoded'}

    conn = self.get_connection(oauth_request.http_url, timeout=70)  # Keep-alives every 30s.
    response = None
    try:
      conn.request(oauth_request.http_method, oauth_request.http_url, body=oauth_request.to_postdata(), headers=headers)
      response = conn.getresponse()
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Connecting to user stream failed. Reason: %s" % repr(err))
    if (response.status == 401):
      raise TwitterAuthError("Connecting to user stream failed. Server response (%d %s)." % (response.status, response.reason))
    elif (response.status != 200):
      raise TwitterHTTPError("Connecting to user stream failed. Server response (%d %s)." % (response.status, response.reason))

    return (conn, response)

  def access_sample_stream(self, oauth_request):
    """Opens an on-going connection to follow the Twitter sample stream.

    :param oauth_request: A POST request, with 'delimited'='length' parameter.
    :returns: An HTTPConnection and HTTPResponse, which should be read immediately.
    :raises: TwitterAuthError, TwitterHTTPError
    """
    if (oauth_request.http_method != "POST"): raise TwitterHTTPError("access_sample_stream() requires a POST request.")
    headers = {'Content-Type' :'application/x-www-form-urlencoded'}

    conn = self.get_connection(oauth_request.http_url, timeout=70)  # Keep-alives every 30s.
    response = None
    try:
      conn.request(oauth_request.http_method, oauth_request.http_url, body=oauth_request.to_postdata(), headers=headers)
      response = conn.getresponse()
    except (httplib.HTTPException) as err:
      conn.close()
      raise TwitterHTTPError("Connecting to sample stream failed. Reason: %s" % repr(err))
    if (response.status == 401):
      raise TwitterAuthError("Connecting to sample stream failed. Server response (%d %s)." % (response.status, response.reason))
    elif (response.status != 200):
      raise TwitterHTTPError("Connecting to sample stream failed. Server response (%d %s)." % (response.status, response.reason))

    return (conn, response)
