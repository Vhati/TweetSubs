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


# Global constants.

# How often, in seconds, pending tweets are checked to display one.
tweet_check_interval = 2

# Max tweet timestamp lag, in seconds.
# Tweets might arrive up to 50s lagged (due to travel time?).
# If tweets come in faster than the check_interval, the backlog will
# be up to this far behind (older tweets will be ignored on each check).
tweet_expiration = 60

# Max in-VLC screentime for each subtitle, in seconds.
osd_duration = 7

# The TCP port VLC will listen on.
vlc_port = 27555

VERSION = "1.04"
INTF_LUA_NAME = "tweetsubs_cli.lua"  # VLC panics if this has a hyphen!?
CONSUMER_KEY = 'y5Okw5ltA6PUe9H1uumA3w'
CONSUMER_SECRET = 'a0r1x7fwbepzaxkaweafGU1Xrpfe6hDFfCnVToUbU'



# Do some basic imports, and set up logging to catch ImportError.
import locale
import logging
import os
import sys

if (__name__ == "__main__"):
  locale.setlocale(locale.LC_ALL, "")

  # Go to the script dir (primary module search path; blank if cwd).
  if (sys.path[0]): os.chdir(sys.path[0])

  logger = logging.getLogger()
  logger.setLevel(logging.DEBUG)

  logstream_handler = logging.StreamHandler()
  logger.addHandler(logstream_handler)
  logstream_formatter = logging.Formatter("%(levelname)s: %(message)s")
  logstream_handler.setFormatter(logstream_formatter)
  logstream_handler.setLevel(logging.INFO)

  logfile_handler = logging.FileHandler("log.txt", mode="w")
  logger.addHandler(logfile_handler)
  logfile_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S")
  logfile_handler.setFormatter(logfile_formatter)

  # __main__ stuff is continued at the end of this file.


# Import everything else (tkinter may be absent on some environments)
try:
  import ConfigParser
  import ctypes
  from datetime import datetime, timedelta
  import errno
  import hashlib
  import htmlentitydefs
  import inspect
  import json
  import platform
  import Queue
  import re
  import select
  import shutil
  import signal
  import socket
  import subprocess
  import threading
  import time
  import tkFont
  import Tkinter as tk
  import tkMessageBox
  import webbrowser

  # Modules bundled with this script.
  from lib import oauth
  from lib import pytwit

except (Exception) as err:
  logging.exception(err)
  sys.exit(1)



class KillableThread(threading.Thread):
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

  def __init__(self, client, connection, response, stream_lines):
    KillableThread.__init__(self)
    self.client = client
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
            tweet["text_clean"] = asciify(html_unescape(tweet["text"]))
            tweet["text_clean"] = re.sub("\r", "", tweet["text_clean"])
            tweet["text_clean"] = re.sub("^ +", "", tweet["text_clean"])
            tweet["text_clean"] = re.sub("^@[^ ]+ *", "", tweet["text_clean"], 1)
            tweet["text_clean"] = re.sub(" *https?://[^ ]+", "", tweet["text_clean"])
            tweet["text_clean"] = tweet["text_clean"].rstrip(" \n")
            msg = tweet["text_clean"]
          if ("created_at" in tweet):
            tweet_time = datetime.strptime(tweet["created_at"] +" UTC", '%a %b %d %H:%M:%S +0000 %Y %Z')

          if ("user" in tweet and "screen_name" in tweet["user"]):
            msg = "%s: %s" % (asciify(tweet["user"]["screen_name"]), msg)

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

class VLCSocketThread(TweetsThread):
  """A thread that sends subtitle/play commands to VLC over a socket."""

  def __init__(self, sleep_interval, expiration, stream_lines, vlc_socket, vlc_port):
    TweetsThread.__init__(self, sleep_interval, expiration, stream_lines)
    # Pseudo enum constants.
    self.ACTIONS = ["ACTION_PLAY"]
    for x in self.ACTIONS: setattr(self, x, x)

    self.vlc_socket = vlc_socket
    self.vlc_port = vlc_port

  def run(self):
    failed_connects = 0
    while (self.keep_alive):
      self.nap(2)
      if (not self.keep_alive): break
      try:
        self.vlc_socket.connect(('127.0.0.1', self.vlc_port))
        break
      except (Exception) as err:
        failed_connects += 1
        if (failed_connects > 7):
          logging.error("%s gave up repeated attempts to connect to VLC on port %s." % (self.__class__.__name__, self.vlc_port))
          self.keep_alive = False
    if (not self.keep_alive): return
    TweetsThread.run(self)

  def show_message(self, text):
    # The lua VLC interface is line-oriented.
    text = re.sub("\n", "\\\\n", text)
    try:
      self.vlc_socket.sendall("osd_msg %s\n" % text)
    except (Exception) as err:
      self.keep_alive = False
      logging.error("%s failed to send VLC an osd_msg command: %s" % (self.__class__.__name__, str(err)))
      return

  def process_event_queue(self, queue_timeout=0.5):
    action_name, arg_dict = None, None
    try:
      queue_block = True if (queue_timeout is not None and queue_timeout > 0) else False
      action_name, arg_dict = self.event_queue.get(queue_block, queue_timeout)
    except (Queue.Empty):
      return

    if (action_name == self.ACTION_PLAY):
      try:
        self.vlc_socket.sendall("play\n")
      except (Exception) as err:
        self.keep_alive = False
        logging.error("%s failed to send VLC a play command: %s" % (self.__class__.__name__, str(err)))
        return

class CleanupHandler():
  """A base class for threadsafe exit/interrupt operations."""

  def __init__(self):
    self.caught_lock = threading.RLock()
    self.caught = False
    # Attach handlers to self, so they won't get garbage collected.

    def signal_handler(signum, stackframe):
      logging.info("Signal handler wants to exit!")
      self.cleanup()
    self.signal_handler = signal_handler

    if (re.search("Windows", platform.system(), re.IGNORECASE)):
      # Handle console window closing.
      #   http://msdn.microsoft.com/en-us/library/ms686016(VS.85).aspx
      #   http://msdn.microsoft.com/en-us/library/ms683242(v=vs.85).aspx
      CTRL_CLOSE_EVENT = 2

      @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)
      def win_ctrlhandler(dwCtrlType):
        if (dwCtrlType == CTRL_CLOSE_EVENT):
          logging.info("ConsoleCtrlHandler wants to exit!")
          self.cleanup()
          return True  # Consume the event to thwart the default handler.
        return False
      self.win_ctrlhandler = win_ctrlhandler
    else:
      self.win_ctrlhandler = None

  def register(self):
    """Associates handler funcs with signals. Call from MainThread."""
    signal.signal(signal.SIGINT, self.signal_handler)
    signal.signal(signal.SIGTERM, self.signal_handler)

    if (re.search("Windows", platform.system(), re.IGNORECASE)):
      ctypes.windll.kernel32.SetConsoleCtrlHandler(self.win_ctrlhandler, 1)

  def cleanup(self):
    """Triggers cleanup. Handlers and Threads call this."""
    with self.caught_lock:
      if (self.caught): return
      self.caught = True

    # If a signal handler called this, we're in MainThread,
    #   blocking mainloop(), so do cleaning up in a separate thread.
    t = threading.Thread(target=self._cleanup, name="CleanupWorker")
    t.start()

  def _cleanup(self):
    """The acutal cleanup code. Subclasses should override this."""
    os._exit(0)


class CustomCleanupHandler(CleanupHandler):
  """A CleanupHandler that understands KillableThreads, sockets,
  subprocess objects, and GuiApps."""

  def __init__(self, killable_threads=[], sockets=[], procs=[], guis=[]):
    CleanupHandler.__init__(self)
    self.threads = killable_threads
    self.sockets = sockets
    self.procs = procs
    self.guis = guis

  def add_thread(self, t):
    with self.caught_lock:
      if (self.caught): self.kill_thread(t)
      elif (t not in self.threads): self.threads.append(t)

  def add_socket(self, s):
    with self.caught_lock:
      if (self.caught): self.kill_socket(s)
      elif (s not in self.sockets): self.sockets.append(s)

  def add_proc(self, p):
    with self.caught_lock:
      if (self.caught): self.kill_proc(p)
      elif (p not in self.procs): self.procs.append(p)

  def add_gui(self, g):
    with self.caught_lock:
      if (self.caught): self.kill_gui(g)
      elif (g not in self.guis): self.guis.append(g)

  def kill_thread(self, t): t.keep_alive = False
  def kill_socket(self, s):
    try:
      s.shutdown(socket.SHUT_WR)
      s.close()
    except (Exception) as err:
      pass
  def kill_proc(self, p):
    if (p.poll() is None):
      try:
        p.terminate()
      except (Exception) as err:
        pass
  def kill_gui(self, g): g.invoke_later(g.ACTION_DIE, {})

  def _cleanup(self):
    try:
      logging.info("")
      logging.info("Quitting... (ctrl-break to be rude)")
      logging.info("")
      for t in self.threads:
        if (t): self.kill_thread(t)
      for s in self.sockets:
        if (s): self.kill_socket(s)
      for p in self.procs:
        if (p): self.kill_proc(p)
      for g in self.guis:
        if (g): self.kill_gui(g)

      # Wait for all the other threads to run out
      #while len([t for t in threading.enumerate() if not t.daemon]) > 1:
      #  time.sleep(0.1)

      # Wait for monitored threads to run out (surprise exit() any others).
      still_waiting = True
      first_pass = True
      while (still_waiting):
        still_waiting = False
        for t in self.threads:
          if (t and t.isAlive() and not t.daemon and t != threading.currentThread()):
            if (not first_pass): logging.info("Waiting on thread: %s" % str(t))
            still_waiting = True
            break
        for g in self.guis:
          if (g and g.done is False):
            if (not first_pass): logging.info("Waiting on GUI: %s" % str(g))
            still_waiting = True
            break
        if (still_waiting): time.sleep(1)
        first_pass = False

    except (IOError) as err:
      if (err.errno == errno.EINTR):  # Ignore sigint'd sleep() on Windows.
        pass
      else:
        logging.exception(err)  #raise

    os._exit(0)  # Exit for real, unlike sys.exit().

class CurrentTimeClock(tk.Label):
  """A clock widget that dynamically shows UTC time."""

  def __init__(self, parent, *args, **kwargs):
    tk.Label.__init__(self, parent, *args, **kwargs)
    self.prev_str = ""
    self.tick()

  def tick(self):
    current_time = datetime.utcnow()
    new_str = current_time.strftime("%H:%M:%S")
    if (new_str != self.prev_str):
      self.prev_str = new_str
      self.config(text=new_str)
    self.alarm_id = self.after(200, self.tick)  # Call again in 200 msec
    # If not cancelled when self is destroyed,
    # See self.after_cancel(self.alarm_id) to put in self._destroy()
    # destroy_id = widget.bind('<Destroy>', self._destroy)


class CountdownClock(tk.Label):
  """A clock widget that dynamically shows distance from a UTC time.
  If target_time=my_datetime isn't passed to the constructor, utcnow()
  is used. If target_time is None, no countdown occurs.
  """

  def __init__(self, parent, *args, **kwargs):
    if ("target_time" not in kwargs):
      kwargs["target_time"] = datetime.utcnow()
    self.target_time = kwargs["target_time"]
    del kwargs["target_time"]

    tk.Label.__init__(self, parent, *args, **kwargs)
    self.prev_str = ""
    if (self.target_time is not None): self.tick()

  def tick(self):
    current_time = datetime.utcnow()
    diff_delta = current_time - self.target_time
    sign = ("+" if (abs(diff_delta) == diff_delta) else "-")
    hours, remainder = divmod(abs(diff_delta).seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    new_str = "%s%d:%02d:%02d" % (sign, hours, minutes, seconds)
    if (new_str != self.prev_str):
      self.prev_str = new_str
      self.config(text=new_str)
    self.alarm_id = self.after(200, self.tick)  # Call again in 200 msec

  def config(self, *args, **kwargs):
    if ("target_time" in kwargs):
      self.target_time = kwargs["target_time"]
      del kwargs["target_time"]
    tk.Label.config(self, *args, **kwargs)

class GuiApp(tk.Frame):
  """A tkinter GUI interface for TweetSubs.
  A separate thread handles logic and controls this widget via invoke_later().
  That thread provides callbacks, to later notify itself how the user responded.

  Referenced Globals: VERSION
  """

  def __init__(self, master=None):
    tk.Frame.__init__(self, master)
    # Pseudo enum constants.
    self.ACTIONS = ["ACTION_SWITCH_WELCOME", "ACTION_SWITCH_PIN",
                    "ACTION_SWITCH_COUNTDOWN", "ACTION_SWITCH_FOLLOW",
                    "ACTION_SWITCH_COMPOSE", "ACTION_SWITCH_COMPOSE_NERFED",
                    "ACTION_COMPOSE_TEXT", "ACTION_WIDGETS_ENABLE",
                    "ACTION_WARN", "ACTION_DIE"]
    for x in self.ACTIONS: setattr(self, x, x)
    self.PHASES = ["PHASE_SPLASH", "PHASE_WELCOME", "PHASE_PIN",
                   "PHASE_COUNTDOWN", "PHASE_FOLLOW", "PHASE_COMPOSE"]
    for x in self.PHASES: setattr(self, x, x)

    global VERSION
    self.VERSION = VERSION

    self.event_queue = Queue.Queue()
    self.tmp_frame = None
    self.state = {}
    self.root = self.winfo_toplevel()
    self.done = False  # Indicates to other threads that mainloop() ended.

    #label = tk.Label(self.root, text="")
    #self.default_font = tkFont.Font(font=label['font'])
    #label.destroy()
    #self.default_font.configure(size="10")
    ##self.default_font = tkFont.Font(family="Times", size="10")
    #print self.default_font.actual()

    self.clpbrd_menu = tk.Menu(self, tearoff=0)
    self.clpbrd_menu.add_command(label="Cut")
    self.clpbrd_menu.add_command(label="Copy")
    self.clpbrd_menu.add_command(label="Paste")
    def show_clpbrd_menu(e):
      w = e.widget
      edit_choice_state = "normal"
      try:
        if (w.cget("state") == "disabled"): edit_choice_state = "disabled"
      except (Exception) as err:
        pass
      self.clpbrd_menu.entryconfigure("Cut", command=lambda: w.event_generate("<<Cut>>"), state=edit_choice_state)
      self.clpbrd_menu.entryconfigure("Copy", command=lambda: w.event_generate("<<Copy>>"))
      self.clpbrd_menu.entryconfigure("Paste", command=lambda: w.event_generate("<<Paste>>"), state=edit_choice_state)
      self.clpbrd_menu.tk.call("tk_popup", self.clpbrd_menu, e.x_root, e.y_root)
    self.bind_class("Entry", "<Button-3><ButtonRelease-3>", show_clpbrd_menu)
    self.bind_class("Text", "<Button-3><ButtonRelease-3>", show_clpbrd_menu)
    self.bind("<<EventEnqueued>>", self.process_event_queue)

    self.pack()
    self.root.resizable(False, False)  # Stops user resizing.
    self.switch_to_splash()

  def switch_to_splash(self):
    self.remove_all()

    self.root.wm_title("TweetSubs %s" % self.VERSION)
    self.state["phase"] = self.PHASE_SPLASH
    self.tmp_frame = tk.Frame(self)
    self.tmp_frame.pack()

    warning_frame = tk.Frame(self.tmp_frame, borderwidth="1",relief="sunken")
    warning_frame.pack(fill="x",expand="yes",pady=("10","0"))

    warning_lbl = tk.Label(warning_frame, text="...")
    warning_lbl.pack(fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

  def switch_to_welcome(self, next_func):
    self.remove_all()

    self.root.wm_title("TweetSubs %s" % self.VERSION)
    self.state["phase"] = self.PHASE_WELCOME
    self.tmp_frame = tk.Frame(self)
    self.tmp_frame.pack()

    notice_str = ""
    notice_str += "This frontend will connect to Twitter, launch VLC, and\n"
    notice_str += "display live @tweets as subtitles over any video you watch.\n"
    notice_str += "\n"
    notice_str += "There may be a slight delay as tweets reach you across the\n"
    notice_str += "internet, so DO NOT touch the seek bar or pause in response\n"
    notice_str += "to them. Start playing on schedule, and let the movie run."
    notice_lbl = tk.Label(self.tmp_frame, text=notice_str)
    notice_lbl.pack(fill="x",expand="yes",pady=("0","10"))

    def next_btn_callback():
      self.set_widgets_enabled(self.PHASE_WELCOME, False)
      next_func({})

    next_btn = tk.Button(self.tmp_frame)
    next_btn["text"] = "Continue"
    next_btn["command"] = next_btn_callback
    next_btn.pack(fill="none",expand="no")
    self.state["next_btn"] = next_btn

    warning_frame = tk.Frame(self.tmp_frame, borderwidth="1",relief="sunken")
    warning_frame.pack(fill="x",expand="yes",pady=("10","0"))

    warning_lbl = tk.Label(warning_frame, text="Note: Closing this window will kill VLC, and vice versa.")
    warning_lbl.pack(fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

    next_btn.bind(sequence="<Return>", func=next_btn["command"])
    next_btn.focus_set()

  def switch_to_pin_prompt(self, next_func, req_token, auth_url):
    self.remove_all()

    self.root.wm_title("TweetSubs - PIN")
    self.state["phase"] = self.PHASE_PIN
    self.tmp_frame = tk.Frame(self)
    self.tmp_frame.pack()

    notice_str = ""
    notice_str += "You need to authorize this application\n"
    notice_str += "to interact with Twitter on your behalf.\n"
    notice_str += "\n"
    notice_str += "Click 'Get a PIN' to open a browser window.\n"
    notice_str += "Then copy the number you receive and paste it here."
    notice_lbl = tk.Label(self.tmp_frame, text=notice_str)
    notice_lbl.pack(fill="x",expand="yes",pady=("0","10"))

    browse_btn = tk.Button(self.tmp_frame)
    browse_btn["text"] = "Get a PIN"
    browse_btn["command"] = lambda : webbrowser.open_new_tab(auth_url)
    browse_btn.pack(fill="none",expand="no")

    pin_next_frame = tk.Frame(self.tmp_frame)
    pin_next_frame.pack(fill="x",expand="yes",pady="5")

    pin_lbl = tk.Label(pin_next_frame, text="PIN:",anchor="e")
    pin_lbl.pack(side="left",fill="none",expand="no",padx=("10","2"))

    pin_field = tk.Entry(pin_next_frame, justify="left",relief="groove")
    pin_field.pack(side="left",fill="x",expand="yes",padx=("0","4"))
    self.state["pin_field"] = pin_field

    def next_btn_callback():
      verifier_string = pin_field.get()
      if (len(verifier_string) > 0):
        self.set_widgets_enabled(self.PHASE_PIN, False)
        self.state["warning_lbl"].config(text="")
        next_func({"req_token":req_token, "verifier_string":verifier_string})

    next_btn = tk.Button(pin_next_frame)
    next_btn["text"] = "Continue"
    next_btn["command"] = next_btn_callback
    next_btn.pack(side="left",fill="none",expand="no",padx=("4","10"))
    self.state["next_btn"] = next_btn

    warning_frame = tk.Frame(self.tmp_frame, borderwidth="1",relief="sunken")
    warning_frame.pack(fill="x",expand="yes",pady=("10","0"))

    warning_lbl = tk.Label(warning_frame, text="")
    warning_lbl.pack(fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

    pin_field.bind(sequence="<Return>", func=next_btn["command"])
    pin_field.focus_set()

  def switch_to_countdown_prompt(self, next_func):
    self.remove_all()

    self.root.wm_title("TweetSubs - Countdown")
    self.state["phase"] = self.PHASE_COUNTDOWN
    self.tmp_frame = tk.Frame(self)
    self.tmp_frame.pack()

    notice_str = ""
    notice_str += "You may schedule VLC to automatically play\n"
    notice_str += "at a time in the future (your local timezone).\n"
    notice_str += "(Leave in the past to opt-out.)\n"
    notice_str += "\n"
    notice_str += "This only covers pressing play, so have the\n"
    notice_str += "video loaded and paused/stopped in advance."
    notice_lbl = tk.Label(self.tmp_frame, text=notice_str)
    notice_lbl.pack(fill="x",expand="yes",pady=("0","10"))

    countdown_next_frame = tk.Frame(self.tmp_frame)
    countdown_next_frame.pack(fill="x",expand="yes",pady="5")

    countdown_lbl = tk.Label(countdown_next_frame, text="Play at:",anchor="e")
    countdown_lbl.pack(side="left",fill="none",expand="no",padx=("10","2"))

    local_now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    local_now_str = re.sub(":[0-9][0-9]$", ":00", local_now_str)

    countdown_field = tk.Entry(countdown_next_frame,justify="left",relief="groove")
    countdown_field.pack(side="left",fill="x",expand="yes",padx=("0","4"))
    countdown_field.insert(0, local_now_str)
    self.state["countdown_field"] = countdown_field

    def next_btn_callback():
      text = countdown_field.get()
      try:
        utc_datetime = None
        if (len(text) > 0):
          local_tuple = time.strptime(text, "%Y-%m-%d %H:%M:%S")
          epoch = time.mktime(local_tuple)
          utc_tuple = time.gmtime(epoch)
          utc_datetime = datetime.utcfromtimestamp(epoch)

        self.set_widgets_enabled(self.PHASE_COUNTDOWN, False)
        self.state["warning_lbl"].config(text="")
        next_func({"countdown_to_time":utc_datetime})
      except (ValueError, OverflowError) as err:
        logging.error("Countdown parsing failed: %s" % str(err));
        self.state["warning_lbl"].config(text="Error: Countdown parsing failed.")

    next_btn = tk.Button(countdown_next_frame)
    next_btn["text"] = "Continue"
    next_btn["command"] = next_btn_callback
    next_btn.pack(side="left",fill="none",expand="no",padx=("4","10"))
    self.state["next_btn"] = next_btn

    warning_frame = tk.Frame(self.tmp_frame, borderwidth="1",relief="sunken")
    warning_frame.pack(fill="x",expand="yes",pady=("10","0"))

    warning_lbl = tk.Label(warning_frame, text="Note: This is in 24-hour time.")
    warning_lbl.pack(fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

    countdown_field.bind(sequence="<Return>", func=next_btn["command"])
    countdown_field.focus_set()

  def switch_to_follow_prompt(self, next_func):
    self.remove_all()

    self.root.wm_title("TweetSubs - Follow")
    self.state["phase"] = self.PHASE_FOLLOW
    self.tmp_frame = tk.Frame(self)
    self.tmp_frame.pack()

    notice_str = ""
    notice_str += "Pick a Twitter user to follow.\n"
    notice_str += "(Leave blank for random chatter.)"
    notice_lbl = tk.Label(self.tmp_frame, text=notice_str)
    notice_lbl.pack(fill="x",expand="yes",pady=("0","10"))

    follow_next_frame = tk.Frame(self.tmp_frame)
    follow_next_frame.pack(fill="x",expand="yes",pady="5")

    follow_lbl = tk.Label(follow_next_frame, text="Follow User:",anchor="e")
    follow_lbl.pack(side="left",fill="none",expand="no",padx=("10","2"))

    follow_field = tk.Entry(follow_next_frame, justify="left",relief="groove")
    follow_field.pack(side="left",fill="x",expand="yes",padx=("0","4"))
    self.state["follow_field"] = follow_field

    def next_btn_callback():
      self.set_widgets_enabled(self.PHASE_FOLLOW, False)
      self.state["warning_lbl"].config(text="")
      next_func({"user_name":follow_field.get()})

    next_btn = tk.Button(follow_next_frame)
    next_btn["text"] = "Continue"
    next_btn["command"] = next_btn_callback
    next_btn.pack(side="left",fill="none",expand="no",padx=("4","10"))
    self.state["next_btn"] = next_btn

    warning_frame = tk.Frame(self.tmp_frame, borderwidth="1",relief="sunken")
    warning_frame.pack(fill="x",expand="yes",pady=("10","0"))

    warning_lbl = tk.Label(warning_frame, text="")
    warning_lbl.pack(fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

    follow_field.bind(sequence="<Return>", func=next_btn["command"])
    follow_field.focus_set()

  def switch_to_compose(self, next_func, text_clean_func, max_length, src_user_name, countdown_to_time):
    self.remove_all()

    self.root.wm_title("TweetSubs - Compose (as %s)" % src_user_name)
    self.state["phase"] = self.PHASE_COMPOSE
    self.tmp_frame = tk.Frame(self)
    self.tmp_frame.pack()

    # Moved whoami reminder from notice_str to window title.
    #notice_str = "Tweeting as %s" % src_user_name
    #notice_lbl = tk.Label(self.tmp_frame, text=notice_str)
    #notice_lbl.pack(fill="x",expand="yes",pady=("0","10"))

    message_send_frame = tk.Frame(self.tmp_frame)
    message_send_frame.pack(fill="x",expand="yes",pady="5")

    text_lbl = tk.Label(message_send_frame, text="Message:",anchor="e")
    text_lbl.pack(side="left",fill="none",expand="no",padx=("10","2"))

    # 35x4 = 140
    message_area = tk.Text(message_send_frame, relief="groove",width="35",height="2")
    message_area.pack(side="left",fill="none",expand="no",padx=("0","4"))
    self.state["message_area"] = message_area

    def send_btn_callback():
      text = message_area.get("1.0", tk.END)[:-1]  # Chop TK-added \n.
      text = re.sub("\n\n+", "\n", text)  # SubRip tolerates multiple lines, but not blank lines.
      if (text_clean_func is not None): text = text_clean_func(text)
      char_count = len(text)
      if (max_length >= 0 and char_count > max_length):
        self.state["warning_lbl"].config(text="Error: Too many characters.")
        return
      self.set_widgets_enabled(self.PHASE_COMPOSE, False)
      self.state["warning_lbl"].config(text="")
      next_func({"text":text})

    send_btn = tk.Button(message_send_frame)
    send_btn["text"] = "Send"
    send_btn["command"] = send_btn_callback
    send_btn.pack(side="left",fill="none",expand="no",padx=("4","10"))
    self.state["send_btn"] = send_btn

    warning_frame = tk.Frame(self.tmp_frame, borderwidth="1",relief="sunken")
    warning_frame.pack(fill="x",expand="yes",pady=("10","0"))

    warning_lbl = tk.Label(warning_frame, text="")
    warning_lbl.pack(side="left",fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

    clock_sep = tk.Frame(warning_frame, border=1,relief="sunken")
    clock_sep.pack(side='left',fill='y',ipadx="1")
    #clock_sep = tk.Label(warning_frame, text="|")
    #clock_sep.pack(side="left",fill="y",expand="no")

    clock_lbl = CountdownClock(warning_frame, text="+0:00:00", target_time=countdown_to_time)
    clock_lbl.pack(side="left",fill="none",expand="no")
    self.state["clock_lbl"] = clock_lbl

    # After each key release, count the chars.
    def message_typed(event):
      text = message_area.get("1.0", tk.END)[:-1]
      text = re.sub("\n\n+", "\n", text)  # SubRip tolerates multiple lines, but not blank lines.
      if (text_clean_func is not None): text = text_clean_func(text)
      char_count = len(text)
      if (max_length >= 0):
        msg = "%d" % (max_length - char_count)
      else:
        msg = "Length: %d" % char_count

      warning_lbl.config(text=msg)
    message_area.bind(sequence="<KeyRelease>", func=message_typed)

    # Use return as a shortcut to send, shift-return for newlines.
    def message_pressed_return(event):
      # Dev note: pressed fires repeatedly, then released fires once.
      if (event.state & 1 > 0):  # Test for shift key in bitmask.
        pass                     # Continue processing normally.
      else:
        return "break"           # Consume the event.
    
    def message_released_return(event):
      if (event.state & 1 > 0):  # Test for shift key in bitmask.
        pass                     # Continue processing normally.
      else:
        send_btn_callback()
        return "break"           # Consume the event.
    message_area.bind(sequence="<Return>", func=message_pressed_return)
    message_area.bind(sequence="<KeyRelease-Return>", func=message_released_return)

    message_area.focus_set()

  def set_widgets_enabled(self, phase, b):
    if ("phase" not in self.state or self.state["phase"] != phase): return
    if (self.state["phase"] == self.PHASE_WELCOME):
      if (b is True):
        self.state["next_btn"].config(state="normal")
      else:
        self.state["next_btn"].config(state="disabled")
    elif (self.state["phase"] == self.PHASE_FOLLOW):
      if (b is True):
        self.state["follow_field"].config(state="normal")
        self.state["follow_field"].delete(0, tk.END)
        self.state["next_btn"].config(state="normal")
      else:
        self.state["follow_field"].config(state="disabled")
        self.state["next_btn"].config(state="disabled")
    elif (self.state["phase"] == self.PHASE_COMPOSE):
      if (b is True):
        self.state["message_area"].config(state="normal",foreground="black")
        self.state["send_btn"].config(state="normal")
      else:
        self.state["message_area"].config(state="disabled",foreground="gray")
        self.state["send_btn"].config(state="disabled")

  def remove_all(self):
    if (self.tmp_frame):
      self.tmp_frame.pack_forget()  # or grid_forget()
      self.tmp_frame.destroy()
      self.tmp_frame = None
    self.state.clear()

  def center_window(self):
    # An event-driven call to this would go nuts with plain update().
    self.root.update_idletasks()
    xp = (self.root.winfo_screenwidth()/2) - (self.root.winfo_width()/2)
    yp = (self.root.winfo_screenheight()/2) - (self.root.winfo_height()/2)
    self.root.geometry('+{0}+{1}'.format(xp, yp))

    # Geometry WxH+X+Y resizes, but any manual sizing disables auto-fit.
    #self.root.geometry('{0}x{1}+{2}+{3}'.format(self.root.winfo_width(), self.root.winfo_height(), xp, yp))
    # To Auto-fit again, clear the geometry.
    #self.root.winfo_toplevel().wm_geometry("")

    # Misc notes...
    #self.pack_propagate(False)  # Tells a widget to ignore its contents' requests to resize.

  # Toggles always on top (Windows only).
  def set_topmost(self, b):
    if (b is True): self.root.attributes('-topmost', 1)
    else: self.root.attributes('-topmost', 0)

  def process_event_queue(self, event):
    """Processes events queued via invoke_later().

    ACTION_SWITCH_WELCOME(next_func)
    ACTION_SWITCH_PIN(next_func, req_token, auth_url)
    ACTION_SWITCH_COUNTDOWN(next_func)
    ACTION_SWITCH_FOLLOW(next_func)
    ACTION_SWITCH_COMPOSE(next_func, text_clean_func, max_length, src_user_name, countdown_to_time)
    ACTION_SWITCH_COMPOSE_NERFED(src_user_name, countdown_to_time)
    ACTION_COMPOSE_TEXT(text)
    ACTION_WARN(message)
    """
    func_or_name, arg_dict = self.event_queue.get()
    def check_args(args):
      for arg in args:
        if (arg not in arg_dict):
          logging.error("Missing %s arg queued to %s %s." % (arg, self.__class__.__name__, func_or_name))
          return False
      return True

    if (hasattr(func_or_name, "__call__")):
      func_or_name(arg_dict)
    elif (func_or_name == self.ACTION_SWITCH_WELCOME):
      if (check_args(["next_func"])):
        self.switch_to_welcome(arg_dict["next_func"])
        self.center_window()
    elif (func_or_name == self.ACTION_SWITCH_PIN):
      if (check_args(["next_func", "req_token", "auth_url"])):
        self.switch_to_pin_prompt(arg_dict["next_func"], arg_dict["req_token"], arg_dict["auth_url"])
        self.center_window()
    elif (func_or_name == self.ACTION_SWITCH_COUNTDOWN):
      if (check_args(["next_func"])):
        self.switch_to_countdown_prompt(arg_dict["next_func"])
        self.center_window()
    elif (func_or_name == self.ACTION_SWITCH_FOLLOW):
      if (check_args(["next_func"])):
        self.switch_to_follow_prompt(arg_dict["next_func"])
        self.center_window()
    elif (func_or_name == self.ACTION_SWITCH_COMPOSE):
      if (check_args(["next_func", "text_clean_func", "max_length", "src_user_name", "countdown_to_time"])):
        self.switch_to_compose(arg_dict["next_func"], arg_dict["text_clean_func"], arg_dict["max_length"], arg_dict["src_user_name"], arg_dict["countdown_to_time"])
        self.center_window()
    elif (func_or_name == self.ACTION_SWITCH_COMPOSE_NERFED):
      if (check_args(["src_user_name", "countdown_to_time"])):
        self.switch_to_compose(lambda x: None, None, 0, arg_dict["src_user_name"], arg_dict["countdown_to_time"])
        self.state["message_area"].delete("1.0", tk.END)
        self.state["message_area"].insert(tk.END, "<< Tweet composition is disabled >>")
        self.set_widgets_enabled(self.PHASE_COMPOSE, False)
        self.center_window()
    elif (func_or_name == self.ACTION_COMPOSE_TEXT):
      if (self.state["phase"] == self.PHASE_COMPOSE and check_args(["text"])):
        self.state["message_area"].delete("1.0", tk.END)
        self.state["message_area"].insert(tk.END, arg_dict["text"])
    elif (func_or_name == self.ACTION_WIDGETS_ENABLE):
      if (check_args(["phase", "b"])):
        self.set_widgets_enabled(arg_dict["phase"], arg_dict["b"])
    elif (func_or_name == self.ACTION_WARN):
      if (check_args(["message"]) and "warning_lbl" in self.state):
        self.state["warning_lbl"].config(text=arg_dict["message"])
    elif (func_or_name == self.ACTION_DIE):
      self.root.destroy()

  # Non-GUI threads can call this.
  def invoke_later(self, func_or_name, arg_dict):
    try:
      self.event_queue.put((func_or_name, arg_dict))
      self.event_generate("<<EventEnqueued>>", when="tail")
      return True
    except (tk.TclError) as err:
      return False


class LogicThread(KillableThread):
  def __init__(self, mygui, cleanup_handler, tweetsubs_data_dir, vlc_path):
    KillableThread.__init__(self)
    self.ACTIONS = ["ACTION_LOAD_CREDS", "ACTION_PIN_AUTH",
                    "ACTION_SET_COUNTDOWN",
                    "ACTION_LOOKUP_USER",
                    "ACTION_FOLLOW_USER", "ACTION_FOLLOW_SAMPLE",
                    "ACTION_SPAWN_VLC", "ACTION_SEND_TWEET",
                    "ACTION_PLAY",
                    "ACTION_REFOLLOW"]
    for x in self.ACTIONS: setattr(self, x, x)

    self.PHASES = ["PHASE_INIT",
                   "PHASE_LOAD_CREDS", "PHASE_PIN_AUTH", "PHASE_AUTHORIZED",
                   "PHASE_SET_COUNTDOWN",
                   "PHASE_FOLLOW_USER", "PHASE_FOLLOW_SAMPLE",
                   "PHASE_SPAWN_VLC",
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
    global CONSUMER_KEY, CONSUMER_SECRET

    try:
      self.stream_lines = StreamLines()
      self.stream_thread = None
      self.vlcsock_thread = None
      self.vlc_proc = None
      self.countdown_to_time = None

      self.client = pytwit.TwitterOAuthClient()
      self.consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
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

      self.mygui.invoke_later(self.mygui.ACTION_SWITCH_WELCOME, {"next_func":self.welcome_prompt_callback})


      while (self.keep_alive):
        self.process_event_queue(0.5)  # Includes some blocking.
        if (not self.keep_alive): break
        if (self.vlcsock_thread and not self.vlcsock_thread.isAlive()): break
        if (self.vlc_proc and self.vlc_proc.poll() is not None): break
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

  def process_event_queue(self, queue_timeout=0.5):
    """Processes events queued via invoke_later().

    ACTION_LOAD_CREDS()
     | \ACTION_PIN_AUTH(req_token, verifier_string)
     |   |
    ACTION_SET_COUNTDOWN(countdown_to_time)
     | \-ACTION_LOOKUP_USER(user_name)
     |   ACTION_FOLLOW_USER(user_name, user_id)
     |                         |
     \-ACTION_FOLLOW_SAMPLE()  |
        |                      |
    ACTION_SPAWN_VLC()       --/
    ACTION_SEND_TWEET(text)
    ---
    ACTION_REFOLLOW
    """
    action_name, arg_dict = None, None
    try:
      queue_block = True if (queue_timeout is not None and queue_timeout > 0) else False
      action_name, arg_dict = self.event_queue.get(queue_block, queue_timeout)
    except (Queue.Empty):
      return

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
        basic_info, _ = self.client.lookup_user(arg_dict["user_name"])
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

      self.phase = self.PHASE_FOLLOW_USER
      self.stream_lines.clear()
      self.followed_user = None
      oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='POST', http_url=self.client.FOLLOW_USER_URL, parameters={"follow":arg_dict["user_id"],"delimited":"length"})
      oauth_request.sign_request(self.signature_method, self.consumer, self.token)

      logging.info("Connecting to Twitter user stream.")
      try:
        conn, response = self.client.access_user_stream(oauth_request)
        self.stream_thread = StreamThread(self, conn, response, self.stream_lines)
        self.stream_thread.set_failure_callback(self.follow_failure_callback)
        self.stream_thread.start()
        self.followed_user = {"user_type":"user", "user_name":arg_dict["user_name"], "user_id":arg_dict["user_id"]}
        self.invoke_later(self.ACTION_SPAWN_VLC, {})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))

        next_func = self.follow_prompt_callback
        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_FOLLOW, {"next_func":next_func})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":("Error: User follow failed: %s" % arg_dict["user"])})

        self.phase  = self.PHASE_LOAD_CREDS  # Revert.

    elif (action_name == self.ACTION_FOLLOW_SAMPLE):
      if (self.phase not in [self.PHASE_SET_COUNTDOWN]): return

      self.phase = self.PHASE_FOLLOW_SAMPLE
      self.stream_lines.clear()
      self.followed_user = None
      oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method='POST', http_url=self.client.FOLLOW_SAMPLE_URL, parameters={"delimited":"length"})
      oauth_request.sign_request(self.signature_method, self.consumer, self.token)

      logging.info("Connecting to Twitter sample stream.")
      try:
        conn, response = self.client.access_sample_stream(oauth_request)
        self.stream_thread = StreamThread(self, conn, response, self.stream_lines)
        self.stream_thread.set_failure_callback(self.follow_failure_callback)
        self.stream_thread.start()
        self.followed_user = {"user_type":"sample"}
        self.invoke_later(self.ACTION_SPAWN_VLC, {})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))

        next_func = self.follow_prompt_callback
        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_FOLLOW, {"next_func":next_func})
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Sample follow failed."})

        self.phase  = self.PHASE_LOAD_CREDS  # Revert.


    elif (action_name == self.ACTION_REFOLLOW):
      if (self.token is None):
        logging.error("Re-following failed. No auth token.")
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Re-following failed. No auth token."})
        return
      if (self.followed_user is None or self.followed_user["user_type"] not in ["user","sample"]):
        logging.error("Re-following failed. Nothing was followed to begin with.")
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Re-following failed. Nothing was followed to begin with."})
        return

      self.stream_lines.clear()

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

        self.stream_thread = StreamThread(self, conn, response, self.stream_lines)
        self.stream_thread.set_failure_callback(self.follow_failure_callback)
        self.stream_thread.start()

        logging.info("Re-following succeeded.")
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Re-following succeeded."})
      except (pytwit.TwitterException) as err:
        logging.error("%s" % str(err))

        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Re-following failed."})


    elif (action_name == self.ACTION_SPAWN_VLC):
      if (self.phase not in [self.PHASE_FOLLOW_USER, self.PHASE_FOLLOW_SAMPLE]): return
      global tweet_check_interval, tweet_expiration, vlc_port, osd_duration
      prev_phase = self.phase

      self.phase = self.PHASE_SPAWN_VLC
      logging.info("Spawning VLC.")
      self.vlc_proc = spawn_vlc(self.vlc_path, vlc_port, osd_duration)
      self.cleanup_handler.add_proc(self.vlc_proc)

      logging.info("Connecting to VLC on port %d." % vlc_port)
      vlc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.vlcsock_thread = VLCSocketThread(tweet_check_interval, tweet_expiration, self.stream_lines, vlc_socket, vlc_port)
      self.vlcsock_thread.start()
      self.cleanup_handler.add_thread(self.vlcsock_thread)
      self.cleanup_handler.add_socket(vlc_socket)

      src_user_name = self.src_user["user_name"]
      if (self.followed_user and self.followed_user["user_type"] == "user"):
        def next_func(arg_dict):
          self.invoke_later(self.ACTION_SEND_TWEET, arg_dict)

        def text_clean_func(text):
          return self.client.get_sanitized_tweet(text)

        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_COMPOSE, {"next_func":next_func,"text_clean_func":text_clean_func,"max_length":self.client.MAX_TWEET_LENGTH,"src_user_name":src_user_name,"countdown_to_time":self.countdown_to_time})
        self.mygui.invoke_later(self.mygui.ACTION_COMPOSE_TEXT, {"text":("@%s " % self.followed_user["user_name"])})
        self.phase = self.PHASE_COMPOSE
      else:
        self.mygui.invoke_later(self.mygui.ACTION_SWITCH_COMPOSE_NERFED, {"src_user_name":src_user_name,"countdown_to_time":self.countdown_to_time})
        self.phase = self.PHASE_COMPOSE_NERFED


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
      if (self.vlcsock_thread is None or self.vlcsock_thread.keep_alive is False):
        logging.error("%s %s was queued, but no TweetsThread is running." % (self.__class__.__name__, action_name))
        self.mygui.invoke_later(self.mygui.ACTION_WARN, {"message":"Error: Scheduled playing failed weirdly."})
        return

      self.vlcsock_thread.invoke_later(self.vlcsock_thread.ACTION_PLAY, {})

  def invoke_later(self, action_name, arg_dict):
    self.event_queue.put((action_name, arg_dict))


def setup_vlc_files():
  """Copies the lua interface script to VLC's per-user data dir."""
  global INTF_LUA_NAME

  src_intf_file = os.path.join("share", INTF_LUA_NAME)
  if (not os.path.isfile(src_intf_file)):
    raise Exception("Could not find VLC lua interface file: %s" % src_intf_file)

  vlc_app_dir = get_gui_app_user_data_dir({"Darwin":"org.videolan.vlc", "Any":"vlc"})
  vlc_intf_dir = os.path.join(vlc_app_dir, "lua", "intf")
  ensure_dir_exists(vlc_intf_dir, 0700)
  vlc_intf_file = os.path.join(vlc_intf_dir, INTF_LUA_NAME)
  if (not os.path.isfile(vlc_intf_file) or (get_file_md5(vlc_intf_file) != get_file_md5(src_intf_file))):
    logging.info("Copying %s to %s." % (src_intf_file, vlc_intf_file))
    shutil.copyfile(src_intf_file, vlc_intf_file)


def get_vlc_dir():
  """Finds VLC.
  Linux: PATH search.
  OSX: See get_osx_app_info() / PATH search.
  Windows: Registry query / PATH search.

  :returns: The path to the VLC executable.
  """
  this_platform = platform.system()
  result_path = None
  result_version = "?.?.?"

  if (re.search("Linux", this_platform, re.IGNORECASE)):
    vlc_path = which("vlc")
    if (vlc_path):
      result_path = vlc_path

  elif (re.search("Darwin", this_platform, re.IGNORECASE)):
    apps = get_osx_app_info("VLC")
    for app in apps:
      vlc_path = app["path"] +"/Contents/MacOS/VLC"
      if (os.path.exists(vlc_path) and os.access(vlc_path, os.X_OK)):
        result_path = vlc_path
        result_version = vlc_version
        break

    if (result_path is None):
      vlc_path = which("vlc")
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
      vlc_path = which("vlc")
      if (vlc_path):
        result_path = vlc_path

  if (result_path is None):
    raise Exception("Could not find the VLC dir.")
  else:
    logging.debug("Found VLC (%s) at: %s" % (result_version, result_path))

  return result_path


def spawn_vlc(vlc_path, vlc_port, osd_duration):
  """Spawns VLC.

  :param vlc_path: Path to the vlc executable.
  :param vlc_port: The port VLC should open for its lua interface script.
  :param osd_duration: Max in-VLC screentime for each subtitle.
  :returns: A subprocess handle.
  """
  global INTF_LUA_NAME

  vlc_dir, vlc_name = os.path.split(vlc_path)
  intf_lua_basename = re.sub("[.][^.]*$", "", INTF_LUA_NAME)

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
  global VERSION

  cleanup_handler = None
  mygui = None

  try:
    logging.info("TweetSubs %s (on %s)" % (VERSION, platform.platform(aliased=True, terse=False)))

    logging.info("Registering ctrl-c handler.")
    cleanup_handler = CustomCleanupHandler()
    cleanup_handler.register()  # Must be called from main thread.
    # Warning: If the main thread gets totally blocked, it'll never notice sigint.

    vlc_path = get_vlc_dir()
    setup_vlc_files()

    tweetsubs_data_dir = get_gui_app_user_data_dir({"Any":"TweetSubs"})
    ensure_dir_exists(tweetsubs_data_dir, 0700)

    root = tk.Tk()
    mygui = GuiApp(master=root)
    root.update()  # No mainloop to auto-update yet.
    mygui.center_window()
    cleanup_handler.add_gui(mygui)

    logic_thread = LogicThread(mygui, cleanup_handler, tweetsubs_data_dir, vlc_path)
    logic_thread.start()

    # Tkinter mainloop doesn't normally die and let its exceptions be caught.
    def tk_error_func(exc, val, tb):
      logging.exception("%s" % exc)
      root.destroy()
    root.report_callback_exception = tk_error_func

    root.mainloop()

  except (Exception) as err:
    logging.exception(err)  #raise

  if (mygui is not None): mygui.done = True
  if (cleanup_handler is not None): cleanup_handler.cleanup()


def html_unescape(text):
  """Removes HTML or XML character references and entities
  from a text string.
  http://effbot.org/zone/re-sub.htm#unescape-html

  :param text: The HTML (or XML) source text.
  :returns: The plain text, as a Unicode string, if necessary.
  """
  def fixup(m):
    text = m.group(0)
    if text[:2] == "&#":
      # character reference
      try:
        if text[:3] == "&#x":
          return unichr(int(text[3:-1], 16))
        else:
          return unichr(int(text[2:-1]))
      except ValueError:
        pass
    else:
      # named entity
      try:
        text = unichr(htmlentitydefs.name2codepoint[text[1:-1]])
      except KeyError:
        pass
    return text # leave as is
  return re.sub("&#?\w+;", fixup, text)


def asciify(utext):
  """Converts a unicode string to ascii, substituting some chars.

  :param utext: A unicode string to convert (harmless if already ascii).
  :returns: An asciified string.
  """
  # To check a char: http://www.eki.ee/letter/chardata.cgi?ucode=2032
  utext = utext.replace(u"\u2013", "-")
  utext = utext.replace(u"\u2014", "-")
  utext = utext.replace(u"\u2018", "'")
  utext = utext.replace(u"\u2019", "'")
  utext = utext.replace(u"\u2032", "'")
  utext = utext.replace(u"\u201c", "\"")
  utext = utext.replace(u"\u201d", "\"")
  utext = utext.replace(u"\u2026", "...")
  # Replace every other non-ascii char with "?".
  text = utext.encode("ASCII", "replace")
  return text


def get_gui_app_user_data_dir(app_name_dict):
  """Gets the GUI app-specific user data directory.

  Win7  C:\User\UserName\Appdata\Roaming\AppName\
  WinXP %USERPROFILE%\Application Data\AppName\
  OSX   ~/Library/Application Support/AppName/
  Linux ${XDG_DATA_HOME}/appname/
    or  ~/.local/share/appname/

  http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html

  :param app_name_dict: Names to use for the app dir, keyed by OS: Linux/Darwin/Windows/Any.
  :returns: A path string.
  :raises: Exception, NotImplementedError, OSError
  """
  this_platform = platform.system()
  data_dir_path = None
  dir_mode = None
  if (re.search("Linux", this_platform, re.IGNORECASE)):
    dir_name = (app_name_dict["Linux"] if ("Linux" in app_name_dict) else app_name_dict["Any"])
    dir_mode = 0700
    parent_path = None

    if (not parent_path):
      parent_path = os.environ.get("XDG_DATA_HOME")
      if (not parent_path):
        parent_path = os.path.expanduser("~")
        if (parent_path != "~"):
          parent_path = os.path.join(parent_path, ".local", "share")
        else:
          parent_path = None

    if (parent_path):
      data_dir_path = os.path.join(parent_path, dir_name)

  elif (re.search("Darwin", this_platform, re.IGNORECASE)):
    dir_name = (app_name_dict["Darwin"] if ("Darwin" in app_name_dict) else app_name_dict["Any"])
    dir_mode = 0700
    parent_path = None

    if (not parent_path):
      parent_path = os.path.expanduser("~")
      if (parent_path != "~"):
        data_dir_path = os.path.join(parent_path, "Library", "Application Support", dir_name)
      else:
        parent_path = None

    if (parent_path):
      data_dir_path = os.path.join(parent_path, dir_name)

  elif (re.search("Windows", this_platform, re.IGNORECASE)):
    dir_name = (app_name_dict["Windows"] if ("Windows" in app_name_dict) else app_name_dict["Any"])
    dir_mode = None
    try:
      from ctypes import wintypes, windll
      CSIDL_APPDATA = 26

      _SHGetFolderPath = windll.shell32.SHGetFolderPathW
      _SHGetFolderPath.argtypes = [wintypes.HWND,
                                   ctypes.c_int, wintypes.HANDLE,
                                   wintypes.DWORD, wintypes.LPCWSTR]
      path_buf = wintypes.create_unicode_buffer(wintypes.MAX_PATH)
      result = _SHGetFolderPath(0, CSIDL_APPDATA, 0, 0, path_buf)
      parent_path = path_buf.value
      parent_path = parent_path.decode(sys.getfilesystemencoding())
    except (ImportError, AttributeError) as err:
      logging.debug("WinAPI querying for user's app data dir failed: %s" % str(err))

    if (parent_path):
      data_dir_path = os.path.join(parent_path, dir_name)
  else:
    raise NotImplementedError("Getting the app data dir is unsupported for this OS: %s" % this_platform)

  if (data_dir_path is None):
    raise Exception("Could not find the user application data dir.")

  return data_dir_path


def ensure_dir_exists(dir_path, dir_mode):
  """Attempts to create a directory and doesn't fail if it exists.

  :param mode: None for os.makedirs() defaults (0700 recommended for user app dir).
  :raises: OSError
  """
  try:
    if (dir_mode is not None):
      os.makedirs(dir_path, dir_mode)
    else:
      os.makedirs(dir_path)
  except (OSError) as err:
    if (err.errno != errno.EEXIST):
      raise


def get_file_md5(path):
  """Gets the md5 hash string of a file."""
  md5 = hashlib.md5()
  with open(path, 'rb') as f:
    for chunk in iter(lambda: f.read(8192), b''):
      md5.update(chunk)
  return md5.hexdigest()


def which(program):
  """Searches PATH for an executable (and PATHEXT extensions).

  :param program: A filename to search for.
  :returns: The program's path, or None.
  """
  def is_exe(fpath):
    return os.path.exists(fpath) and os.access(fpath, os.X_OK)

  def ext_candidates(fpath):
    yield fpath
    for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
      yield fpath + ext

  fpath, fname = os.path.split(program)
  if fpath:
    if is_exe(program):
      return program
  else:
    for path in os.environ["PATH"].split(os.pathsep):
      exe_file = os.path.join(path, program)
      for candidate in ext_candidates(exe_file):
        if is_exe(candidate):
          return candidate

  return None


def get_osx_app_info(app_name):
  """Finds apps by calling OSX's system_profiler command.

  :returns: A list of name/path/version dicts, reverse sorted by version.
  """
  import plistlib

  try:
    command = ["system_profiler", "-xml", "SPApplicationsDataType"]
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    stdout, unused_stderr = p.communicate()

    if (task.returncode != 0): return None

    apps = plistlib.readPlistFromString(stdout)[0]["_items"]

    version_segments = 1
    candidates = []
    for app in apps:
      if "_name" in app and "path" in app and "version" in app:
        # app["_name"]   # QuickTime Player
                         # VLC
        # app["path"]    # /Volumes/Macintosh HD/Applications/QuickTime Player.app
                         # /Applications/VLC.app
                         # /Volumes/HD/Applications/VLC.app
        # app["version"] # 2.0.1
                         # 1.1.12
        if (app["_name"] == app_name and os.path.exists(app["path"])):
          candidates.append({"name":app["_name"], "path":app["path"], "version":app["version"]})
          version_segments = max(version_segments, len(app["version"].split(".")))

    def key_func(x):
      v = x["version"]
      if (not v): v = "0"
      v += ".0" * (version_segments - len(v.split(".")))
      chunks = v.split(".")
      for i in range(len(chunks)):
        if (re.match("^[0-9]+$", chunks[i])): chunks[i] = int(chunks[i])
      return chunks

    return sorted(candidates, key=key_func, reverse=True)
  except (Exception) as err:
    raise



if (__name__ == "__main__"):
  main()
