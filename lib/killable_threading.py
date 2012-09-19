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
  """A base class for threads that die when self.keep_alive is False."""
  def __init__(self):
    threading.Thread.__init__(self)
    self.keep_alive = True


class StreamThread(KillableThread):
  """Consumes a length-DELIMITED live twitter stream (filter.json/sample.json).
  ---
  14\r\n
  {json stuff}\r\n
  ---
  And so on (empty \r\n-terminated lines may precede each delimiter).

  Non-delimited streams only lack the number line, but CPU usage spikes on busy
  streams, reading 1 byte at a time.
  """

  def __init__(self, connection, response, stream_lines):
    KillableThread.__init__(self)
    self.connection = connection
    self.response = response
    self.stream_lines = stream_lines
    self.is_length_delimited = True  # I don't feel like exposing this as an arg.
    self.failure_func = None
    self.daemon = True  # Workaround for select()'s lies.

  def run(self):
    in_delim = self.is_length_delimited
    block_size = 1  # Unless delimiter says so, expect no more than 1 readable byte.
    delim_buffers = []
    #read_objs = [self.response.fp.fileno()]
    #read_objs = [self.connection.sock]
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
        if (self.keep_alive and self.failure_func is not None):
          logging.debug("%s is calling its failure func..." % self.__class__.__name__)
          self.failure_func({})
        self.keep_alive = False
        continue

      if (do_read):
        try:
          block = self.response.read(block_size)
          #block = self.connection.sock.recv(block_size)
        except (Exception) as err:
          logging.error("%s ended. Reason: %s" % (self.__class__.__name__, str(err)))
          if (self.keep_alive and self.failure_func is not None):
            logging.debug("%s is calling its failure func..." % self.__class__.__name__)
            self.failure_func({})
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
          self.stream_lines.append_block(block)
          if (self.is_length_delimited):  # in_delim stays false if not delimited.
            block_size -= len(block)  # Allow for interrupted reads.
            if (block_size <= 0):
              in_delim = True
              block_size = 1

    self.connection.close()

  def set_failure_callback(self, failure_func):
    """Sets an optional function to call when the socket dies."""
    self.failure_func = failure_func


class StreamLines():
  """A thread-safe FIFO stack that can be appended and popped."""

  def __init__(self):
    self.lock = threading.RLock()
    self.lines = []
    self.buffers = []
    self.line_ptn = re.compile("([^\r]*)(?:\r\n)?")

  def size(self):
    with self.lock:
      return len(self.lines)

  def clear(self):
    with self.lock:
      del self.lines[:]
      del self.buffers[:]

  def append_block(self, block):
    with self.lock:
      for g in re.finditer(self.line_ptn, block):
        self.append_line(g.group(0))

  def append_line(self, line):
    with self.lock:
      if (line.endswith("\r\n")):
        self.buffers.append(line)
        self.lines.append(''.join(self.buffers).rstrip(" \r\n"))
        del self.buffers[:]
      else:
        self.buffers.append(line)

  def pop_line(self):
    with self.lock:
      if (len(self.lines) > 0):
        return self.lines.pop(0)
      else:
        return None


class TweetsThread(KillableThread):
  """A thread that periodically pops messages off a StreamLines stack.
  Subclasses should override show_message() and optionally
  process_event_queue().
  """

  def __init__(self, sleep_interval, expiration, stream_lines):
    KillableThread.__init__(self)
    self.sleep_interval = sleep_interval
    self.stream_lines = stream_lines
    self.expire_delta = timedelta(seconds=expiration)
    self.event_queue = Queue.Queue()

  # Sleep intermittently while checking stuff, if seconds is an integer.
  def nap(self, seconds):
    slept = 0.0
    while (slept < seconds):
      amt = min(0.5, (seconds-slept))
      time.sleep(amt)
      slept += amt
      if (not self.keep_alive): break
      self.process_event_queue(0)

  def run(self):
    try:
      while (self.keep_alive):
        self.nap(self.sleep_interval)
        if (not self.keep_alive): break
        self.process_event_queue(0)

        while(self.keep_alive):
          # Keep popping until a valid unexpired tweet is found.
          line = self.stream_lines.pop_line()
          if (line is None): break
          if (len(line) == 0): continue

          tweet = None
          try:
            tweet = json.loads(line)
            tweet["text_clean"] = ""
          except (TypeError, ValueError) as err:
            logging.info("Tweet parsing failed: %s" % repr(line))
            continue

          msg = ""
          tweet_time = 0
          if ("text" in tweet):
            tweet["text_clean"] = common.asciify(common.html_unescape(tweet["text"]))
            tweet["text_clean"] = re.sub("\r", "", tweet["text_clean"])
            tweet["text_clean"] = re.sub("^ +", "", tweet["text_clean"])
            tweet["text_clean"] = re.sub("^@[^ ]+ *", "", tweet["text_clean"], 1)
            tweet["text_clean"] = re.sub(" *https?://[^ ]+", "", tweet["text_clean"])
            tweet["text_clean"] = tweet["text_clean"].rstrip(" \n")
            if (re.match("^[? ]{4,}$", tweet["text_clean"])):
              continue  # Likely tons of non-ascii chars. Skip.
            msg = tweet["text_clean"]
          if ("created_at" in tweet):
            tweet_time = datetime.strptime(tweet["created_at"] +" UTC", '%a %b %d %H:%M:%S +0000 %Y %Z')

          if ("user" in tweet and "screen_name" in tweet["user"]):
            msg = "%s: %s" % (common.asciify(tweet["user"]["screen_name"]), msg)

          if (len(tweet["text_clean"]) > 0):
            current_time = datetime.utcnow()
            lag_delta = (current_time - tweet_time)
            lag_str = ""
            if (abs(lag_delta) == lag_delta):  # Tweet in past, positive lag.
              lag_str = "%ds" % lag_delta.seconds
            elif (lag_delta.days == -1 and (tweet_time - current_time).seconds == 0):
              lag_str = "0s"                   # Tweet was only microseconds ahead, call it 0.
            else:                              # Tweet in future, negative lag (-1 day, 86400-Nsecs).
              lag_str = "-%ds" % (tweet_time - current_time).seconds

            if (lag_delta > self.expire_delta):
              logging.info("Tweet expired (lag %s): %s" % (lag_str, msg))
              continue
            else:
              logging.info("Tweet shown (lag %s): %s" % (lag_str, msg))
              self.show_message(msg)
              break
            #logging.info("Time(Current): %s  Time(Tweet): %s" % (current_time.strftime("%a %b %d %Y %H:%M:%S"), tweet_time.strftime("%a %b %d %Y %H:%M:%S")))
            #logging.info("---")

    except (Exception) as err:
      logging.exception("Unexpected exception in %s." % self.__class__.__name__)  #raise
      self.keep_alive = False

  def show_message(self, text):
    print text

  def process_event_queue(self, queue_timeout=0.5):
    pass

  def invoke_later(self, action_name, arg_dict):
    self.event_queue.put((action_name, arg_dict))
