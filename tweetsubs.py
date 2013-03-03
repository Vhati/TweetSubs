#!/usr/bin/env python

"""
TweetSubs - A frontend to launch VLC, connect to Twitter,
and display live @tweets as subtitles.

Copyright (C) 2012 David Millis
See license.txt for the GNU GENERAL PUBLIC LICENSE

Requires:
  Windows, Linux, or possibly OSX.
  Python 2.6 or higher, but not 3.x.
  VLC 2.x.x

This file does not need to be edited by users.

"""


# Do some basic imports, and set up logging to catch ImportError.
import inspect
import locale
import logging
import os
import sys

if (__name__ == "__main__"):
  locale.setlocale(locale.LC_ALL, "")

  # Tkinter chokes on non-US locales with commas for decimal points.
  #   http://bugs.python.org/issue10647
  #   Fixed in Python 3.2.
  #
  locale.setlocale(locale.LC_NUMERIC, "C")  # Use period for numbers.

  # Get the un-symlinked, absolute path to this module.
  self_folder = os.path.realpath(os.path.abspath(os.path.split(inspect.getfile( inspect.currentframe() ))[0]))
  if (self_folder not in sys.path): sys.path.insert(0, self_folder)

  # Go to this module's dir.
  os.chdir(self_folder)

  logger = logging.getLogger()
  logger.setLevel(logging.DEBUG)

  logstream_handler = logging.StreamHandler()
  logstream_formatter = logging.Formatter("%(levelname)s: %(message)s")
  logstream_handler.setFormatter(logstream_formatter)
  logstream_handler.setLevel(logging.INFO)
  logger.addHandler(logstream_handler)

  logfile_handler = logging.FileHandler(os.path.join(self_folder, "log.txt"), mode="w")
  logfile_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S")
  logfile_handler.setFormatter(logfile_formatter)
  logger.addHandler(logfile_handler)

  # __main__ stuff is continued at the end of this file.


# Import everything else (tkinter may be absent in some environments).
try:
  import ConfigParser
  import ctypes
  from datetime import datetime, timedelta
  import errno
  import inspect
  import json
  import platform
  import Queue
  import re
  import shutil
  import signal
  import socket
  import subprocess
  import threading
  import time
  import tkFont
  import Tkinter as tk
  import tkMessageBox

  # Modules bundled with this script.
  from lib import common
  from lib import cleanup
  from lib import global_config
  from lib import killable_threading
  from lib import oauth
  from lib import osutils
  from lib import pytwit
  from lib import tkwidgets
  from lib import tsgui

except (Exception) as err:
  logging.exception(err)
  sys.exit(1)



class VLCControl(object):
  """Sends commands to VLC over a socket to a lua interface."""
  def __init__(self):
    self._socket_lock = threading.RLock()
    self._vlc_socket = None
    self._failure_func = None

  def set_socket(self, vlc_socket):
    """Sets the socket to communicate with. (thread-safe)
    Any existing socket will be closed.

    When the socket is None (default) communication
    methods do nothing.
    """
    with self._socket_lock:
      if (self._vlc_socket is not None):
        self._vlc_socket.close()
      self._vlc_socket = vlc_socket

  def play(self):
    """Tells VLC to play stopped/paused meda."""
    with self._socket_lock:
      if (self._vlc_socket is None): return

      try:
        self._vlc_socket.sendall("play\n")
      except (Exception) as err:
        self.keep_alive = False
        logging.error("%s failed to send VLC a play command: %s" % (self.__class__.__name__, str(err)))
        return

  def show_message(self, text):
    """Show an osd message over video. (thread-safe)"""
    with self._socket_lock:
      if (self._vlc_socket is None): return

      # The lua VLC interface is line-oriented.
      text = re.sub("\n", "\\\\n", text)

      try:
        self._vlc_socket.sendall("osd_msg %s\n" % text)
      except (Exception) as err:
        logging.error("%s failed to send VLC an osd_msg command: %s" % (self.__class__.__name__, str(err)))
        self.set_socket(None)
        if (self._failure_func is not None):
          logging.debug("%s is calling its failure func..." % self.__class__.__name__)
          self._failure_func({})
        return

  def set_failure_callback(self, failure_func):
    """Sets an optional function to call when the socket dies.
    It will receive one arg, an empty dict.
    """
    self._failure_func = failure_func


class TweetsVLCListener(killable_threading.TweetsListener):
  """A listener for TweetsThreads that forwards to a VLCControl."""
  def __init__(self, vlc_control):
    killable_threading.TweetsListener.__init__(self)
    self.vlc_control = vlc_control

  def on_tweet(self, user_str, msg_str, tweet_json):
    """Responds to incoming tweets. (thread-safe)
    See: killable_threading.TweetsThread.add_tweet_listener().

    :param user_str: The cleaned "screen_name" of the user.
    :param msg_str: The cleaned "text" of the tweet.
    :param tweet_json: The raw json object.
    """
    self.vlc_control.show_message("%s: %s" % (user_str, msg_str))


class TweetsInfoListener(killable_threading.TweetsListener):
  """A listener for TweetsThreads that collects info about the stream."""
  def __init__(self):
    killable_threading.TweetsListener.__init__(self)
    self._info_lock = threading.RLock()
    self._user_list = []

  def add_user(self, user_str):
    """Adds a known user. (thread-safe)"""
    with self._info_lock:
      if (user_str not in self._user_list):
        self._user_list.append(user_str)

  def get_users(self):
    """Returns a copy of the list of all known users. (thread-safe)"""
    with self._info_lock:
      return self._user_list[:]

  def on_tweet(self, user_str, msg_str, tweet_json):
    """Responds to incoming tweets. (thread-safe)
    See: killable_threading.TweetsThread.add_tweet_listener().

    :param user_str: The cleaned "screen_name" of the user.
    :param msg_str: The cleaned "text" of the tweet.
    :param tweet_json: The raw json object.
    """
    self.add_user(user_str)


class TweetsGuiListener(killable_threading.TweetsListener):
  """A listener for TweetsThreads that forwards to a GuiApp."""
  def __init__(self, myapp):
    killable_threading.TweetsListener.__init__(self)
    self.myapp = myapp

  def on_tweet(self, user_str, msg_str, tweet_json):
    """Responds to incoming tweets. (thread-safe)
    See: killable_threading.TweetsThread.add_tweet_listener().

    :param user_str: The cleaned "screen_name" of the user.
    :param msg_str: The cleaned "text" of the tweet.
    :param tweet_json: The raw json object.
    """
    self.myapp.invoke_later(self.myapp.ACTION_NEW_TWEET, {"user_str":user_str, "msg_str":msg_str, "tweet_json":tweet_json})


class LogicThread(killable_threading.KillableThread):
  def __init__(self, mygui, cleanup_handler, tweetsubs_data_dir, vlc_path):
    killable_threading.KillableThread.__init__(self)
    self.ACTIONS = ["ACTION_LOAD_CREDS", "ACTION_PIN_AUTH",
                    "ACTION_SET_COUNTDOWN",
                    "ACTION_LOOKUP_USER",
                    "ACTION_FOLLOW_USER", "ACTION_FOLLOW_SAMPLE",
                    "ACTION_COMPOSE",
                    "ACTION_SPAWN_VLC", "ACTION_SEND_TWEET",
                    "ACTION_SET_VLC_SOCKET", "ACTION_PLAY",
                    "ACTION_REFOLLOW"]
    for x in self.ACTIONS: setattr(self, x, x)

    self.PHASES = ["PHASE_INIT",
                   "PHASE_LOAD_CREDS", "PHASE_PIN_AUTH", "PHASE_AUTHORIZED",
                   "PHASE_SET_COUNTDOWN",
                   "PHASE_FOLLOWED_USER", "PHASE_FOLLOWED_SAMPLE",
                   "PHASE_COMPOSE", "PHASE_COMPOSE_NERFED"]
    for x in self.PHASES: setattr(self, x, x)

    self.mygui = mygui
    self.cleanup_handler = cleanup_handler
    self.tweetsubs_data_dir = tweetsubs_data_dir
    self.vlc_path = vlc_path
    self.config_path = os.path.join(self.tweetsubs_data_dir, "credentials.cfg")
    self.event_queue = Queue.Queue()
    self.phase = self.PHASE_INIT
    self.cleanup_handler.add_thread(self)

  def run(self):
    try:
      self.stream_lines = killable_threading.StreamLines()
      self.stream_thread = None
      self.vlc_proc = None
      self.countdown_to_time = None

      self.tweets_thread = killable_threading.TweetsThread(global_config.tweet_check_interval, global_config.tweet_expiration, self.stream_lines)
      self.tweets_thread.start()
      self.cleanup_handler.add_thread(self.tweets_thread)

      def vlc_control_failure_callback(arg_dict):
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Failed to communicate with VLC."})
        self.invoke_later(self.ACTION_SET_VLC_SOCKET, {"socket":None})
      self.vlc_control = VLCControl()
      self.vlc_control.set_failure_callback(vlc_control_failure_callback)

      self.tweets_vlc_listener = TweetsVLCListener(self.vlc_control)
      # This will be added/removed by ACTION_SET_VLC_SOCKET.

      self.tweets_gui_listener = TweetsGuiListener(self.mygui)
      self.tweets_thread.add_tweet_listener(self.tweets_gui_listener)

      self.tweets_info_listener = TweetsInfoListener()
      self.tweets_thread.add_tweet_listener(self.tweets_info_listener)

      self.client = pytwit.TwitterOAuthClient()
      self.consumer = oauth.OAuthConsumer(global_config.CONSUMER_KEY, global_config.CONSUMER_SECRET)
      self.signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()  # Twitter only likes SHA1.
      self.token = None
      self.src_user = None  # Dict remembers user name/id associated with the token.
      self.followed_user = None  # Dict remembers sample/user's type/name/id.

      def follow_prompt_callback(arg_dict):
        if ("user_name" in arg_dict and len(arg_dict["user_name"]) > 0):
          self.invoke_later(self.ACTION_LOOKUP_USER, {"user_name":arg_dict["user_name"]})
        else:
          self.invoke_later(self.ACTION_FOLLOW_SAMPLE, {})
      self.follow_prompt_callback = follow_prompt_callback

      def welcome_prompt_callback(arg_dict):
        self.invoke_later(self.ACTION_LOAD_CREDS, {})
      self.welcome_prompt_callback = welcome_prompt_callback

      def follow_failure_callback(arg_dict):
        # Spawn the reconnect prompt in the gui thread.
        def prompt_func(arg_dict):
          result = tkMessageBox.askretrycancel(parent=self.mygui, title="TweetSubs - Reconnect?", message="The Twitter stream you were following has disconnected.\nWithout it, you will no longer see incoming tweets.\nDo you want to reconnect?", default=tkMessageBox.RETRY, icon=tkMessageBox.ERROR)
          if (result is True):
            self.invoke_later(self.ACTION_REFOLLOW, {})
          else:
            logging.info("Re-following declined by user.")
            self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Re-following declined by user."})
        self.mygui.invoke_later(prompt_func, {})
      self.follow_failure_callback = follow_failure_callback

      self.mygui.invoke_later(self.mygui.ACTION_SETUP_IGNORE_USERS, {"get_all_users_func":self.tweets_info_listener.get_users,
                                                                     "get_ignored_users_func":self.tweets_thread.get_ignored_users,
                                                                     "set_ignored_users_func":self.tweets_thread.set_ignored_users})
      def vlc_spawn_callback():
        self.invoke_later(self.ACTION_SPAWN_VLC, {})
      self.vlc_spawn_callback = vlc_spawn_callback
      self.mygui.invoke_later(self.mygui.ACTION_SETUP_SPAWN_VLC, {"spawn_func":self.vlc_spawn_callback})

      self.mygui.invoke_later(self.mygui.ACTION_SWITCH_WELCOME, {"next_func":self.welcome_prompt_callback})


      while (self.keep_alive):
        self._process_event_queue(0.5)  # Includes some blocking.
        if (not self.keep_alive): break
        #if (self.vlc_proc and self.vlc_proc.poll() is not None): break
        if (self.mygui.done is True): break

        if (self.countdown_to_time):
          current_time = datetime.utcnow()
          diff_delta = current_time - self.countdown_to_time
          sign = ("+" if (abs(diff_delta) == diff_delta) else "-")
          if (sign == "+"):
            self.countdown_to_time = None
            self.invoke_later(self.ACTION_PLAY, {})

    except (Exception) as err:
      logging.exception("Unexpected exception in %s." % self.__class__.__name__)  #raise

    self.keep_alive = False
    self.cleanup_handler.cleanup()


  def save_credentials(self):
    config = ConfigParser.RawConfigParser()
    config.add_section("Credentials")
    config.set("Credentials", "oauth_key", self.token.key)
    config.set("Credentials", "oauth_secret", self.token.secret)
    config.set("Credentials", "user_name", self.src_user["user_name"])
    config.set("Credentials", "user_id", self.src_user["user_id"])
    try:
      with open(self.config_path, "wb") as f: config.write(f)
    except (Exception) as err:
      logging.error("Could not save credentials: %s" % str(err))

  def _process_event_queue(self, queue_timeout=None):
    """Processes every pending event on the queue.

    :param queue_timeout: Optionally block up to N seconds in the initial check.
    """
    action_name, arg_dict = None, None
    first_pass = True
    while(True):
      try:
        if (first_pass):
          queue_block = True if (queue_timeout is not None and queue_timeout > 0) else False
          action_name, arg_dict = self.event_queue.get(queue_block, queue_timeout)
        else:
          first_pass = False
          action_name, arg_dict = self.event_queue.get_nowait()
      except (Queue.Empty):
        break
      else:
        self._process_event(action_name, arg_dict)

  def _process_event(self, action_name, arg_dict):
    """Processes events queued via invoke_later().

    Most actions depend on the current PHASE and run in order.
    ACTION_LOAD_CREDS()
     | \ACTION_PIN_AUTH(req_token, verifier_string)
     |   |
    ACTION_SET_COUNTDOWN(countdown_to_time)
     | |-ACTION_LOOKUP_USER(user_name)
     | \-ACTION_FOLLOW_USER(user_name, user_id)
     |                         |
     \-ACTION_FOLLOW_SAMPLE()  |
        |                      |
    ACTION_COMPOSE()         --/
    ACTION_SEND_TWEET(text), if following a user.
    ---
    The following don't have timing restrictions:
    ACTION_SPAWN_VLC()
    ACTION_SET_VLC_SOCKET(), when a socket to VLC (dis)connected.
    ACTION_REFOLLOW(), when a StreamThread disconnects.
    """
    if (action_name == self.ACTION_LOAD_CREDS):
      if (self.phase not in [self.PHASE_INIT]): return

      self.phase = self.PHASE_LOAD_CREDS
      self.token = None
      self.src_user = None

      config = ConfigParser.RawConfigParser()
      try:
        if (config.read([self.config_path])):  # Silently skips on failure.
          if (config.has_section("Credentials")):
            k = config.get("Credentials", "oauth_key")
            s = config.get("Credentials", "oauth_secret")
            u = config.get("Credentials", "user_name")
            i = config.get("Credentials", "user_id")
            if (k and s and u and i):
              self.token = oauth.OAuthToken(k, s)
              self.src_user = {"user_id":i, "user_name":u}
      except (Exception) as err:
        logging.error("Could not parse %s: %s" % (self.config_path, str(err)))

      if (self.token is not None):
        try:
          logging.info("Checking saved credentials.")

          oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='GET', http_url=self.client.VERIFY_CREDENTIALS_URL, parameters={})
          oauth_request.sign_request(self.signature_method, self.consumer, self.token)
          basic_user_info, _ = self.client.verify_credentials(oauth_request)
          self.src_user = basic_user_info
        except (Exception) as err:
          logging.error("%s" % str(err))
          self.token = None
          self.src_user = None

      if (self.token is not None): self.save_credentials()

      req_token = None
      auth_url = None
      if (self.token is None):
        try:
          logging.info("Fetching a request token.")
          oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, callback="oob", http_url=self.client.REQUEST_TOKEN_URL)
          oauth_request.sign_request(self.signature_method, self.consumer, None)
          req_token = self.client.fetch_request_token(oauth_request)

          logging.info("Using request token to build authorization url.")
          auth_url = self.client.get_authorization_url(req_token)
        except (Exception) as err:
          logging.error("%s" % str(err))
          req_token = None
          auth_url = None

      if (self.token is not None):
        # Loaded creds, okay to continue.
        def next_func(arg_dict):
          self.invoke_later(self.ACTION_SET_COUNTDOWN, arg_dict)

        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_COUNTDOWN, {"next_func":next_func})
        self.phase = self.PHASE_AUTHORIZED
      elif (req_token is not None and auth_url is not None):
        # Authing from scratch. Prompt for PIN.
        def next_func(arg_dict):
          self.invoke_later(self.ACTION_PIN_AUTH, arg_dict)

        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_PIN, {"next_func":next_func,"req_token":req_token,"auth_url":auth_url})
      else:
        # Forget this happened.
        self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_WELCOME, "b":True})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Failed to establish Twitter credentials."})

        self.phase = self.PHASE_INIT  # Revert.

    elif (action_name == self.ACTION_PIN_AUTH):
      if (self.phase not in [self.PHASE_LOAD_CREDS]): return
      for arg, is_bad in [("req_token", (lambda x:x is None)), ("verifier_string", (lambda x:len(x)==0))]:
        if (arg not in arg_dict or is_bad(arg)):
          logging.error("Bad/missing %s arg queued to %s %s." % (arg, self.__class__.__name__, action_name))
          self.mygui.invoke_later(self.mygui.ACTION_SWITCH_WELCOME, {"next_func":self.welcome_prompt_callback})
          self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: PIN auth failed weirdly."})
          return

      self.phase = self.PHASE_PIN_AUTH

      logging.info("Using PIN to fetch an access token.")
      try:
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=arg_dict["req_token"], verifier=arg_dict["verifier_string"], http_url=self.client.ACCESS_TOKEN_URL)
        oauth_request.sign_request(self.signature_method, self.consumer, arg_dict["req_token"])
        self.token, self.src_user = self.client.fetch_access_token(oauth_request)

        self.save_credentials()

        def next_func(arg_dict):
          self.invoke_later(self.ACTION_SET_COUNTDOWN, arg_dict)

        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_COUNTDOWN, {"next_func":next_func})
        self.phase = self.PHASE_AUTHORIZED
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))
        self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_PIN, "b":True})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: PIN auth failed."})

        self.phase = self.PHASE_LOAD_CREDS  # Revert.

    elif (action_name == self.ACTION_SET_COUNTDOWN):
      if (self.phase not in [self.PHASE_AUTHORIZED]): return
      for arg, is_bad in [("countdown_to_time", (lambda x:False))]:
        if (arg not in arg_dict or is_bad(arg)):
          logging.error("Bad/missing %s arg queued to %s %s." % (arg, self.__class__.__name__, action_name))
          self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Countdown setting failed weirdly."})
          return

      self.phase = self.PHASE_SET_COUNTDOWN

      self.countdown_to_time = None
      current_time = datetime.utcnow()
      diff_delta = current_time - arg_dict["countdown_to_time"]
      sign = ("+" if (abs(diff_delta) == diff_delta) else "-")
      if (sign == "-"):
        self.countdown_to_time = arg_dict["countdown_to_time"]
      else:
        logging.info("Ignoring countdown in the past.")

      next_func = self.follow_prompt_callback
      self.mygui.invoke_later(self.mygui.ACTION_SWITCH_FOLLOW, {"next_func":next_func})

    elif (action_name == self.ACTION_LOOKUP_USER):
      if (self.phase not in [self.PHASE_SET_COUNTDOWN]): return
      for arg, is_bad in [("user_name", (lambda x:len(x)==0))]:
        if (arg not in arg_dict or is_bad(arg)):
          logging.error("Bad/missing %s arg queued to %s %s." % (arg, self.__class__.__name__, action_name))
          self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_FOLLOW, "b":True})
          self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: User lookup failed weirdly."})
          return

      try:
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='GET', http_url=self.client.LOOKUP_USER_URL, parameters={"screen_name":arg_dict["user_name"]})
        oauth_request.sign_request(self.signature_method, self.consumer, self.token)

        basic_info, _ = self.client.lookup_user(oauth_request)
        logging.info("Looked up Twitter user: %s = %s" % (basic_info["user_name"], basic_info["user_id"]))
        self.invoke_later(self.ACTION_FOLLOW_USER, {"user_name":basic_info["user_name"], "user_id":basic_info["user_id"]})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))
        self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_FOLLOW, "b":True})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":("Error: User lookup failed: %s" % arg_dict["user_name"])})

    elif (action_name == self.ACTION_FOLLOW_USER):
      if (self.phase not in [self.PHASE_SET_COUNTDOWN]): return
      len_func = lambda x:len(x)==0
      for arg, is_bad in [("user_name", len_func), ("user_id", len_func)]:
        if (arg not in arg_dict or is_bad(arg)):
          logging.error("Bad/missing %s arg queued to %s %s." % (arg, self.__class__.__name__, action_name))
          self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: User following failed weirdly."})
          return

      self.phase = self.PHASE_FOLLOWED_USER
      self.stream_lines.clear()
      if (self.stream_thread is not None):
        if (self.stream_thread.isAlive()):
          self.stream_thread.stop_living()
        self.stream_thread = None
      self.followed_user = None

      oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='POST', http_url=self.client.FOLLOW_USER_URL, parameters={"follow":arg_dict["user_id"],"delimited":"length"})
      oauth_request.sign_request(self.signature_method, self.consumer, self.token)

      logging.info("Connecting to Twitter user stream.")
      try:
        conn, response = self.client.access_user_stream(oauth_request)
        self.stream_thread = killable_threading.StreamThread(conn, response, self.stream_lines)
        self.stream_thread.set_failure_callback(self.follow_failure_callback)
        self.stream_thread.start()
        self.followed_user = {"user_type":"user", "user_name":arg_dict["user_name"], "user_id":arg_dict["user_id"]}

        self.invoke_later(self.ACTION_COMPOSE, {})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))

        next_func = self.follow_prompt_callback
        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_FOLLOW, {"next_func":next_func})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":("Error: User follow failed: %s" % arg_dict["user"])})

        self.phase  = self.PHASE_SET_COUNTDOWN  # Revert.

        if (self.stream_thread is not None):
          if (self.stream_thread.isAlive()):
            self.stream_thread.stop_living()
          self.stream_thread = None
        self.followed_user = None

    elif (action_name == self.ACTION_FOLLOW_SAMPLE):
      if (self.phase not in [self.PHASE_SET_COUNTDOWN]): return

      self.phase = self.PHASE_FOLLOWED_SAMPLE
      self.stream_lines.clear()
      if (self.stream_thread is not None):
        if (self.stream_thread.isAlive()):
          self.stream_thread.stop_living()
        self.stream_thread = None
      self.followed_user = None

      oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='POST', http_url=self.client.FOLLOW_SAMPLE_URL, parameters={"delimited":"length"})
      oauth_request.sign_request(self.signature_method, self.consumer, self.token)

      logging.info("Connecting to Twitter sample stream.")
      try:
        conn, response = self.client.access_sample_stream(oauth_request)
        self.stream_thread = killable_threading.StreamThread(conn, response, self.stream_lines)
        self.stream_thread.set_failure_callback(self.follow_failure_callback)
        self.stream_thread.start()
        self.followed_user = {"user_type":"sample"}

        self.invoke_later(self.ACTION_COMPOSE, {})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))

        next_func = self.follow_prompt_callback
        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_FOLLOW, {"next_func":next_func})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Sample follow failed."})

        self.phase  = self.PHASE_SET_COUNTDOWN  # Revert.

        if (self.stream_thread is not None):
          if (self.stream_thread.isAlive()):
            self.stream_thread.stop_living()
          self.stream_thread = None
        self.followed_user = None

    elif (action_name == self.ACTION_COMPOSE):
      if (not self.src_user or "user_name" not in self.src_user or not self.src_user["user_name"]):
        logging.error("Bad/missing src_user[\"user_name\"] when %s invoked %s." % (self.__class__.__name__, action_name))
        return

      if (self.followed_user is not None and self.followed_user["user_type"] == "user"):
        # Followed a user, regular compose gui.
        self.phase = self.PHASE_COMPOSE
        def next_func(arg_dict):
          self.invoke_later(self.ACTION_SEND_TWEET, arg_dict)

        def text_clean_func(text):
          return self.client.get_sanitized_tweet(text)

        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_COMPOSE, {"next_func":next_func,"text_clean_func":text_clean_func,"max_length":self.client.MAX_TWEET_LENGTH,"src_user_name":self.src_user["user_name"],"countdown_to_time":self.countdown_to_time})
        self.mygui.invoke_later(self.mygui.ACTION_COMPOSE_TEXT, {"text":("@%s " % self.followed_user["user_name"])})

      else:
        # Followed sample, nerfed compose gui.
        self.phase = self.PHASE_COMPOSE_NERFED
        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_COMPOSE_NERFED, {"src_user_name":self.src_user["user_name"],"countdown_to_time":self.countdown_to_time})

    elif (action_name == self.ACTION_REFOLLOW):
      if (self.token is None):
        logging.error("Re-following failed. No auth token.")
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Re-following failed. No auth token."})
        return
      if (self.followed_user is None or self.followed_user["user_type"] not in ["user","sample"]):
        logging.error("Re-following failed. No user/sample was followed to begin with.")
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Re-following failed. No user/sample was followed to begin with."})
        return

      self.stream_lines.clear()
      if (self.stream_thread is not None):
        if (self.stream_thread.isAlive()):
          self.stream_thread.stop_living()
        self.stream_thread = None

      logging.info("Reconnecting to previously followed Twitter stream.")
      try:
        conn, response = None, None
        if (self.followed_user["user_type"] == "user"):
          oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='POST', http_url=self.client.FOLLOW_USER_URL, parameters={"follow":self.followed_user["user_id"],"delimited":"length"})
          oauth_request.sign_request(self.signature_method, self.consumer, self.token)
          conn, response = self.client.access_user_stream(oauth_request)
        elif (self.followed_user["user_type"] == "sample"):
          oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='POST', http_url=self.client.FOLLOW_SAMPLE_URL, parameters={"delimited":"length"})
          oauth_request.sign_request(self.signature_method, self.consumer, self.token)
          conn, response = self.client.access_sample_stream(oauth_request)

        self.stream_thread = killable_threading.StreamThread(conn, response, self.stream_lines)
        self.stream_thread.set_failure_callback(self.follow_failure_callback)
        self.stream_thread.start()

        logging.info("Re-following succeeded.")
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Re-following succeeded."})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Re-following failed."})

        if (self.stream_thread is not None):
          if (self.stream_thread.isAlive()):
            self.stream_thread.stop_living()
          self.stream_thread = None

    elif (action_name == self.ACTION_SPAWN_VLC):
      if (self.vlc_proc and self.vlc_proc.poll() is None):
        logging.error("An instance of VLC is still running.")
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: An instance of VLC is still running."})
        return

      logging.info("Spawning VLC.")
      self.vlc_proc = spawn_vlc(self.vlc_path, global_config.INTF_LUA_NAME, global_config.vlc_port, global_config.osd_duration)
      self.cleanup_handler.add_proc(self.vlc_proc)

      self.mygui.invoke_later(self.mygui.ACTION_SETUP_SPAWN_VLC, {"spawn_func":None})

      logging.info("Connecting to VLC on port %d." % global_config.vlc_port)
      def success_callback(arg_dict):
        self.invoke_later(self.ACTION_SET_VLC_SOCKET, {"socket":arg_dict["socket"]})
      def failure_callback(arg_dict):
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Failed to connect to VLC."})
        if (self.vlc_proc and self.vlc_proc.poll() is None):
          logging.debug("Terminating unreachable VLC process.")
          try:
            self.vlc_proc.terminate()
          except (Exception) as err:
            pass
      connect_thread = killable_threading.SocketConnectThread("VLC", "127.0.0.1", global_config.vlc_port, 7, 2)
      connect_thread.set_success_callback(success_callback)
      connect_thread.set_failure_callback(failure_callback)
      connect_thread.start()
      self.cleanup_handler.add_thread(connect_thread)
      self.cleanup_handler.add_socket(connect_thread._socket)

      def proc_done_callback():
        if (connect_thread.isAlive()):
          logging.info("VLC is no longer running. Aborting remaining connection attempts.")
          connect_thread.stop_living()
        self.invoke_later(self.ACTION_SET_VLC_SOCKET, {"socket":None})
        self.mygui.invoke_later(self.mygui.ACTION_SETUP_SPAWN_VLC, {"spawn_func":self.vlc_spawn_callback})
      procwatch_thread = killable_threading.ProcessWatchThread("VLC", self.vlc_proc, proc_done_callback)
      procwatch_thread.start()
      self.cleanup_handler.add_thread(procwatch_thread)

    elif (action_name == self.ACTION_SET_VLC_SOCKET):
      for arg, is_bad in [("socket", (lambda x:False))]:
        if (arg not in arg_dict or is_bad(arg)):
          logging.error("Bad/missing %s arg queued to %s %s." % (arg, self.__class__.__name__, action_name))
          return

      self.vlc_control.set_socket(arg_dict["socket"])
      if (not self.tweets_thread):
        logging.error("Bad/missing tweets_thread when %s invoked %s." % (self.__class__.__name__, action_name))
      else:
        if (arg_dict["socket"] is not None):
          self.tweets_thread.add_tweet_listener(self.tweets_vlc_listener)
        else:
          self.tweets_thread.remove_tweet_listener(self.tweets_vlc_listener)

    elif (action_name == self.ACTION_SEND_TWEET):
      if (self.phase not in [self.PHASE_COMPOSE]): return
      for arg, is_bad in [("text", (lambda x:len(x)==0))]:
        if (arg not in arg_dict or is_bad(arg)):
          logging.error("Bad/missing %s arg queued to %s %s." % (arg, self.__class__.__name__, action_name))
          self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_COMPOSE, "b":True})
          self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Tweet sending failed."})
          return
      if (self.followed_user is None or self.followed_user["user_type"] != "user"):
        logging.error("%s %s but no user was followed." % (self.__class__.__name__, action_name))
        self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_COMPOSE, "b":True})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Tweet sending failed."})
        return

      text_clean = self.client.get_sanitized_tweet(arg_dict["text"])
      oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='POST', http_url=self.client.SEND_TWEET_URL, parameters={"status":text_clean})
      oauth_request.sign_request(self.signature_method, self.consumer, self.token)

      logging.info("Sending Tweet: %s" % text_clean)
      try:
        self.client.send_tweet(oauth_request)
        self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_COMPOSE, "b":True})
        self.mygui.invoke_later(self.mygui.ACTION_COMPOSE_TEXT, {"text":("@%s " % self.followed_user["user_name"])})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Tweet sending succeeded."})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))
        self.mygui.invoke_later(self.mygui.ACTION_WIDGETS_ENABLE, {"phase":self.mygui.PHASE_COMPOSE, "b":True})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Tweet sending failed."})

    elif (action_name == self.ACTION_PLAY):
      self.vlc_control.play()

  def invoke_later(self, action_name, arg_dict):
    """Schedules an action to occur in this thread. (thread-safe)"""
    self.event_queue.put((action_name, arg_dict))


def setup_vlc_files(intf_lua_name):
  """Copies the lua interface script to VLC's per-user data dir."""
  src_intf_file = os.path.join("share", intf_lua_name)
  if (not os.path.isfile(src_intf_file)):
    raise Exception("Could not find VLC lua interface file: %s" % src_intf_file)

  vlc_app_dir = osutils.get_gui_app_user_data_dir({"Darwin":"org.videolan.vlc", "Any":"vlc"})
  vlc_intf_dir = os.path.join(vlc_app_dir, "lua", "intf")
  osutils.ensure_dir_exists(vlc_intf_dir, 0700)
  vlc_intf_file = os.path.join(vlc_intf_dir, intf_lua_name)
  if (not os.path.isfile(vlc_intf_file) or (osutils.get_file_md5(vlc_intf_file) != osutils.get_file_md5(src_intf_file))):
    logging.info("Copying %s to %s." % (src_intf_file, vlc_intf_file))
    shutil.copyfile(src_intf_file, vlc_intf_file)


def get_vlc_dir():
  """Finds VLC.
  Linux: PATH search.
  OSX: See osutils.get_osx_app_info() / PATH search.
  Windows: Registry query / PATH search.

  :returns: The path to the VLC executable.
  """
  this_platform = platform.system()
  result_path = None
  result_version = "?.?.?"

  if (re.search("Linux", this_platform, re.IGNORECASE)):
    vlc_path = osutils.which("vlc")
    if (vlc_path):
      result_path = vlc_path

  elif (re.search("Darwin", this_platform, re.IGNORECASE)):
    apps = osutils.get_osx_app_info("VLC")
    for app in apps:
      vlc_path = app["path"] +"/Contents/MacOS/VLC"
      if (os.path.exists(vlc_path) and os.access(vlc_path, os.X_OK)):
        result_path = vlc_path
        result_version = vlc_version
        break

    if (result_path is None):
      vlc_path = osutils.which("vlc")
      if (vlc_path):
        result_path = vlc_path

  elif (re.search("Windows", this_platform, re.IGNORECASE)):
    import _winreg

    # For _winreg.KEY_ALL_ACCESS on Win7, UAC interferes until disabled+reboot.
    for reg_key_path in ["SOFTWARE\\VideoLAN\\VLC", "SOFTWARE\\Wow6432Node\\VideoLAN\\VLC"]:
      try:
        reg_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, reg_key_path, 0, _winreg.KEY_READ)
        path_value, path_type = _winreg.QueryValueEx(reg_key, "")  # "" = Default subkey.
        version_value, version_type = _winreg.QueryValueEx(reg_key, "Version")
        if (path_type == _winreg.REG_SZ and path_value):
          vlc_path = path_value  # Unicode string.
          if (os.path.exists(vlc_path) and os.access(vlc_path, os.X_OK)):
            vlc_version = "?.?.?"
            if (version_type == _winreg.REG_SZ and version_value):
              vlc_version = version_value
            result_path = vlc_path
            result_version = vlc_version
            break
      except (WindowsError) as err:
        pass  #logging.exception(err)  # raise

    if (result_path is None):
      vlc_path = osutils.which("vlc")
      if (vlc_path):
        result_path = vlc_path

  if (result_path is None):
    raise Exception("Could not find the VLC dir.")
  else:
    logging.debug("Found VLC (%s) at: %s" % (result_version, result_path))

  return result_path


def spawn_vlc(vlc_path, intf_lua_name, vlc_port, osd_duration):
  """Spawns VLC.

  :param vlc_path: Path to the vlc executable.
  :param vlc_port: The port VLC should open for its lua interface script.
  :param osd_duration: Max in-VLC screentime for each subtitle.
  :returns: A subprocess handle.
  """
  vlc_dir, vlc_name = os.path.split(vlc_path)
  intf_lua_basename = re.sub("[.][^.]*$", "", intf_lua_name)

  # Redirect streams to oblivion.
  # As of Python 3.3, std streams can be set to subprocess.DEVNULL
  fnull = open(os.devnull, 'w')  # Linux '/dev/null' or Windows nul
  command = [vlc_path]
  command.extend(["--extraintf", "luaintf"])
  command.extend(["--lua-intf", intf_lua_basename])
  command.extend(["--lua-config", ("%s={host='127.0.0.1:%d',osd_duration=%d}" % (intf_lua_basename, vlc_port, osd_duration))])

  vlc_proc = subprocess.Popen(command, shell=False, universal_newlines=True, cwd=vlc_dir, stdin=subprocess.PIPE, stdout=fnull, stderr=fnull, bufsize=1)
  return vlc_proc


def main():
  cleanup_handler = None

  try:
    logging.info("TweetSubs %s (on %s)" % (global_config.VERSION, platform.platform(aliased=True, terse=False)))

    logging.info("Registering ctrl-c handler.")
    cleanup_handler = cleanup.CustomCleanupHandler()
    cleanup_handler.register()  # Must be called from main thread.
    # Warning: If the main thread gets totally blocked, it'll never notice sigint.

    vlc_path = get_vlc_dir()
    setup_vlc_files(global_config.INTF_LUA_NAME)

    tweetsubs_data_dir = osutils.get_gui_app_user_data_dir({"Any":"TweetSubs"})
    osutils.ensure_dir_exists(tweetsubs_data_dir, 0700)

    root = tk.Tk()
    root.withdraw()

    # Tkinter mainloop doesn't normally die and let its exceptions be caught.
    def tk_error_func(exc, val, tb):
      logging.exception("%s" % exc)
      root.destroy()
    root.report_callback_exception = tk_error_func

    mygui = tsgui.GuiApp(master=root)
    mygui.update()  # No mainloop to auto-update yet.
    mygui.center_window()
    cleanup_handler.add_gui(mygui)

    logic_thread = LogicThread(mygui, cleanup_handler, tweetsubs_data_dir, vlc_path)
    logic_thread.start()

    try:
      root.mainloop()
    finally:
      mygui.done = True

  except (Exception) as err:
    logging.exception(err)  #raise

  finally:
    if (cleanup_handler is not None): cleanup_handler.cleanup()



if (__name__ == "__main__"):
  main()
