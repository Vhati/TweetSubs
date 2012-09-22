from datetime import datetime, timedelta
import json
import logging
import Queue
import re
import select
import socket
import threading
import time

from lib import common


class KillableThread(threading.Thread):
  """A base class for threads that die on command.
  Subclasses' run() loops test if self.keep_alive is False.

  Instead of sleeping, they should call nap().

  And any subclass method, meant to be called by other
  threads, that interrupts a nap() should include wake_up().
  """
  def __init__(self):
    threading.Thread.__init__(self)
    self.snooze_cond = threading.Condition()
    self.keep_alive = True

  def nap(self, seconds):
    """Sleep but stay responsive.

    This sleep is preempted by a call to wake_up().

    According to this site, timeouts for Queues,
    Conditions, etc., can waste CPU cycles polling
    excessively often (20x/sec). But you'd need
    hundreds of threads to have a problem.
    http://blog.codedstructure.net/2011/02/concurrent-queueget-with-timeouts-eats.html

    :param seconds: How long to wait. Or None for indefinite.
    """
    with self.snooze_cond:
      self.snooze_cond.wait(seconds)

  def wake_up(self):
    """Interrupts a nap(). (thread-safe)"""
    with self.snooze_cond:
      self.snooze_cond.notify()

  def stop_living(self):
    """Tells this thread to die. (thread-safe)

    This method is preferred over setting keep_alive directly,
    for the benefit of threads that need to sleep with interruption.
    """
    self.keep_alive = False
    self.wake_up()


class StreamThread(KillableThread):
  """Consumes a length-DELIMITED live twitter stream (filter.json/sample.json).
  ---
  14\r\n
  {json stuff}\r\n
  ---
  And so on (empty \r\n-terminated lines may precede each delimiter).

  Non-delimited streams only lack the number line, but CPU usage spikes on busy
  streams, reading 1 byte at a time.

  Because select() proved unreliable, this thread blocks awaiting chars.
  Because blocking may stall shutdown, this is a daemon thread.
  """

  def __init__(self, connection, response, stream_lines):
    KillableThread.__init__(self)
    self._connection = connection
    self._response = response
    self._stream_lines = stream_lines
    self._is_length_delimited = True  # I don't feel like exposing this as an arg.
    self._failure_func = None
    self.daemon = True  # Workaround for select()'s lies.

  def run(self):
    in_delim = self._is_length_delimited
    block_size = 1  # Unless delimiter says so, expect no more than 1 readable byte.
    delim_buffers = []
    #read_objs = [self._response.fp.fileno()]
    #read_objs = [self._connection.sock]
    block = None

    prev = None
    while (self.keep_alive):
      do_read = False
      try:
        # FIXME: Select works for one char, of an incoming burst of data.
        #        Then it falsely reports nothing to read until the next burst.
        #        HTTPConnections' socket-based file-like object has 0-bufsize.
        #        And connection.sock.recv(n) doesn't help. Data seems to be
        #        buffered SOMEWHERE, so select sees everything was read, yet I
        #        haven't asked for it yet. Length delimiters mitigate CPU abuse,
        #        at least.
        #r, _, _ = select.select(read_objs, [], [], 0.5)
        r = True  # Hardcoded true means blocking stalls keep_alive checks (daemon now).
        do_read = bool(r)
      except (socket.error) as err:
        logging.error("%s ended. Reason: %s" % (self.__class__.__name__, str(err)))
        if (self.keep_alive and self._failure_func is not None):
          logging.debug("%s is calling its failure func..." % self.__class__.__name__)
          self._failure_func({})
        self.keep_alive = False
        continue

      if (do_read):
        try:
          block = self._response.read(block_size)
          #block = self._connection.sock.recv(block_size)
        except (Exception) as err:
          logging.error("%s ended. Reason: %s" % (self.__class__.__name__, str(err)))
          if (self.keep_alive and self._failure_func is not None):
            logging.debug("%s is calling its failure func..." % self.__class__.__name__)
            self._failure_func({})
          self.keep_alive = False
          continue
        if (not self.keep_alive): break

        #print repr(block)  #  sanity check for debugging select vs daemon-reads.
        if (in_delim):
          delim_buffers.append(block)
          if (len(delim_buffers) >= 2 and delim_buffers[-2] == "\r" and delim_buffers[-1] == "\n"):
            if (len(delim_buffers) > 2):
              delim_str = ''.join(delim_buffers).rstrip(" \r\n")
              try:
                delim_int = int(delim_str)
                if (delim_int <= 0): raise ValueError("Delimiter not a positive integer.")

                in_delim = False
                block_size = delim_int
              except (ValueError) as err:
                logging.error("%s glitched. Reason: %s. Line: %s" % (self.__class__.__name__, str(err), delim_str))
            else:
              pass  # Empty keep-alive line. Keep waiting for a delimiter.

            del delim_buffers[:]
        else:
          self._stream_lines.append_block(block)
          if (self._is_length_delimited):  # in_delim stays false if not delimited.
            block_size -= len(block)  # Allow for interrupted reads.
            if (block_size <= 0):
              in_delim = True
              block_size = 1

    self._connection.close()

  def set_failure_callback(self, failure_func):
    """Sets an optional function to call when the socket dies.
    It will receive one arg, an empty dict.
    """
    self._failure_func = failure_func


class StreamLines():
  """A thread-safe FIFO stack that can be appended and popped."""

  def __init__(self):
    self.lock = threading.RLock()
    self.lines = []
    self._buffers = []
    self._line_ptn = re.compile("([^\r]*)(?:\r\n)?")

  def size(self):
    with self.lock:
      return len(self.lines)

  def clear(self):
    with self.lock:
      del self.lines[:]
      del self._buffers[:]

  def append_block(self, block):
    """Tokenizes a text block into lines and appends each."""
    with self.lock:
      for g in re.finditer(self._line_ptn, block):
        self.append_line(g.group(0))

  def append_line(self, line):
    """Appends a line to the stack.
    If the line doesn't end with \r\n, it will instead be
    appended to a holding buffer.

    If it does end with \r\n, the buffer will be prepended
    to it, the line break stripped, and the result added to
    the stack.
    """
    with self.lock:
      if (line.endswith("\r\n")):
        self._buffers.append(line)
        self.lines.append(''.join(self._buffers).rstrip(" \r\n"))
        del self._buffers[:]
      else:
        self._buffers.append(line)

  def pop_line(self):
    with self.lock:
      if (len(self.lines) > 0):
        return self.lines.pop(0)
      else:
        return None


class TweetsThread(KillableThread):
  """A thread that periodically pops json messages off a StreamLines stack.
  Subclasses should override show_message() and optionally
  process_event_queue().
  """

  def __init__(self, sleep_interval, expiration, stream_lines):
    KillableThread.__init__(self)
    self._sleep_interval = sleep_interval
    self._stream_lines = stream_lines
    self._expire_delta = timedelta(seconds=expiration)
    self._listeners_lock = threading.RLock()
    self._listeners = []
    self._options_lock = threading.RLock()
    self._ignored_users = []

  def run(self):
    try:
      while (self.keep_alive):
        self.nap(self._sleep_interval)
        if (not self.keep_alive): break

        while(self.keep_alive):
          # Keep popping until a valid unexpired tweet is found.
          line = self._stream_lines.pop_line()
          if (line is None): break
          if (len(line) == 0): continue

          tweet = None
          try:
            tweet = json.loads(line)
          except (TypeError, ValueError) as err:
            logging.info("Tweet parsing failed: %s" % repr(line))
            continue

          user_clean = None
          text_clean = None
          tweet_time = 0
          user_is_ignored = False
          if ("user" in tweet and "screen_name" in tweet["user"]):
            user_clean = common.asciify(tweet["user"]["screen_name"])
            with self._options_lock:
              if (user_clean in self._ignored_users):
                user_is_ignored = True

          if ("text" in tweet):
            text_clean = common.asciify(common.html_unescape(tweet["text"]))
            text_clean = re.sub("\r", "", text_clean)
            text_clean = re.sub("^ +", "", text_clean)
            text_clean = re.sub("^@[^ ]+ *", "", text_clean, 1)
            text_clean = re.sub(" *https?://[^ ]+", "", text_clean)
            text_clean = text_clean.rstrip(" \n")
            if (re.match("^[? .\n\"]{8,}$", text_clean)):
              continue  # Likely tons of non-ascii chars. Skip.

          if ("created_at" in tweet):
            tweet_time = datetime.strptime(tweet["created_at"] +" UTC", '%a %b %d %H:%M:%S +0000 %Y %Z')

          if (user_clean and text_clean and tweet_time):
            current_time = datetime.utcnow()
            lag_delta = (current_time - tweet_time)
            lag_str = ""
            if (abs(lag_delta) == lag_delta):  # Tweet in past, positive lag.
              lag_str = "%ds" % lag_delta.seconds
            elif (lag_delta.days == -1 and (tweet_time - current_time).seconds == 0):
              lag_str = "0s"                   # Tweet was only microseconds ahead, call it 0.
            else:                              # Tweet in future, negative lag (-1 day, 86400-Nsecs).
              lag_str = "-%ds" % (tweet_time - current_time).seconds

            if (lag_delta > self._expire_delta):
              logging.info("Tweet expired (lag %s): %s: %s" % (lag_str, user_clean, text_clean))
              continue
            elif (user_is_ignored):
              logging.info("Tweet ignored (lag %s): %s: %s" % (lag_str, user_clean, text_clean))
              continue
            else:
              logging.info("Tweet shown (lag %s): %s: %s" % (lag_str, user_clean, text_clean))
              self._show_message(user_clean, text_clean, tweet)
              break
            #logging.info("Time(Current): %s  Time(Tweet): %s" % (current_time.strftime("%a %b %d %Y %H:%M:%S"), tweet_time.strftime("%a %b %d %Y %H:%M:%S")))
            #logging.info("---")

    except (Exception) as err:
      logging.exception("Unexpected exception in %s." % self.__class__.__name__)  #raise
      self.keep_alive = False

  def add_tweet_listener(self, listener):
    """Adds a tweet listener. (thread-safe)

    :param listener: An object with an on_tweet(user_str, msg_str, tweet_json) method.
    """
    if (not hasattr(listener, "on_tweet") or not hasattr(listener.on_tweet, "__call__")):
      logging.error("%s cannot listen to %s because it lacks an on_tweet method." % (listener.__class__.__name__, self.__class__.__name__))
      return

    with self._listeners_lock:
      if (listener not in self._listeners):
        self._listeners.append(listener)

  def remove_tweet_listener(self, listener):
    """Removes a tweet listener. (thread-safe)"""
    with self._listeners_lock:
      try:
        self._listeners.remove(listener)
      except (ValueError) as err:
        pass

  def _show_message(self, user_str, msg_str, tweet_json):
    """Sends a new tweet to all listeners.
    :param user_str: The cleaned "screen_name" of the user.
    :param msg_str: The cleaned "text" of the tweet.
    :param tweet_json: The raw json object.
    """
    with self._listeners_lock:
      for listener in self._listeners:
        listener.on_tweet(user_str, msg_str, tweet_json)

  def set_ignored_users(self, user_list):
    """Sets ignored users' names by copying the contents of a new list. (thread-safe)"""
    if (user_list is None): user_list = []
    with self._options_lock:
      self._ignored_users[:] = user_list[:]

  def get_ignored_users(self):
    """Returns a copy of the list of ignored users' names. (thread-safe)"""
    with self._options_lock:
      return self._ignored_users[:]


class SocketConnectThread(KillableThread):
  """Connects to a server and returns a socket.
  :param description: A descriptive string for logging.
  :param server_addr: Server's ip address string.
  :param server_port: Server's port number.
  :param retries: Maximum connection attempts.
  :param retry_interval: Delay in seconds between retries.
  """
  def __init__(self, description, server_addr, server_port, retries, retry_interval):
    KillableThread.__init__(self)
    self._description = description
    self._server_addr = server_addr
    self._server_port = server_port
    self._retries = retries
    self._retry_interval = retry_interval
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self._success_func = None
    self._failure_func = None

  def run(self):
    failed_connects = 0
    while (self.keep_alive):
      self.nap(self._retry_interval)
      if (not self.keep_alive): break
      try:
        self._socket.connect((self._server_addr, self._server_port))
        if (self._success_func is not None):
          logging.debug("%s (%s) is calling its success func..." % (self.__class__.__name__, self._description))
          self._success_func({"socket":self._socket})
        break
      except (socket.error) as err:
        failed_connects += 1
        if (failed_connects >= self._retries):
          logging.error("%s (%s) gave up repeated attempts to connect to %s:%s." % (self.__class__.__name__, self._description, self._server_addr, self._server_port))
          self.keep_alive = False

  def set_success_callback(self, success_func):
    """Sets an optional function to call after giving up connecting.
    It will receive one arg, a {"socket":socket} dict.
    """
    self._success_func = success_func

  def set_failure_callback(self, failure_func):
    """Sets an optional function to call after giving up connecting.
    It will receive one arg, an empty dict.
    """
    self._failure_func = failure_func
