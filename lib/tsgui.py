from datetime import datetime, timedelta
import logging
import Queue
import re
import time
import Tkinter as tk
import tkMessageBox
import webbrowser

from lib import global_config
from lib import tkwidgets


class GuiApp(tk.Toplevel):
  """A tkinter GUI interface for TweetSubs.
  A separate thread handles logic and controls this window via invoke_later().
  That thread provides callbacks, to later notify itself how the user responded.
  """

  def __init__(self, master=None):
    tk.Toplevel.__init__(self, master)
    # Pseudo enum constants.
    self.ACTIONS = ["ACTION_SWITCH_WELCOME", "ACTION_SWITCH_PIN",
                    "ACTION_SWITCH_COUNTDOWN", "ACTION_SWITCH_FOLLOW",
                    "ACTION_SWITCH_COMPOSE", "ACTION_SWITCH_COMPOSE_NERFED",
                    "ACTION_COMPOSE_TEXT", "ACTION_WIDGETS_ENABLE",
                    "ACTION_WARN", "ACTION_NEW_TWEET",
                    "ACTION_SETUP_IGNORE_USERS",
                    "ACTION_SETUP_SPAWN_VLC",
                    "ACTION_DIE"]
    for x in self.ACTIONS: setattr(self, x, x)
    self.PHASES = ["PHASE_SPLASH", "PHASE_WELCOME", "PHASE_PIN",
                   "PHASE_COUNTDOWN", "PHASE_FOLLOW", "PHASE_COMPOSE"]
    for x in self.PHASES: setattr(self, x, x)

    self.MENU_IGNORE_USERS = "Ignore Users..."
    self.MENU_COMMENTARY = "Floating Commentary..."
    self.MENU_SPAWN_VLC = "Launch VLC..."

    self.VERSION = global_config.VERSION

    self._event_queue = Queue.Queue()
    self.tmp_frame = None
    self.state = {}
    self.done = False  # Indicates to other threads that mainloop() ended.

    self._menubar = tk.Menu(self)
    self._options_menu = tk.Menu(self._menubar, tearoff="no")
    self._options_menu.add_command(label=self.MENU_IGNORE_USERS, state="disabled")
    self._options_menu.add_separator()
    self._options_menu.add_command(label=self.MENU_COMMENTARY, state="disabled")
    self._options_menu.add_command(label=self.MENU_SPAWN_VLC, state="disabled")
    self._menubar.add_cascade(label="Options",menu=self._options_menu,underline="0")
    self.config(menu=self._menubar)

    self._menu_funcs = {}   # Settable callbacks for menuitem clicks.
    self._menu_lookup = {}  # Lookup parent menus by menuitem labels.
    self._menu_lookup[self.MENU_IGNORE_USERS] = self._options_menu
    self._menu_lookup[self.MENU_COMMENTARY] = self._options_menu
    self._menu_lookup[self.MENU_SPAWN_VLC] = self._options_menu

    self._caption_window = None
    self.set_menu_callback(self.MENU_COMMENTARY, self._show_caption_window)

    self._menubar_sep = tk.Frame(self, borderwidth="1",relief="groove",height=2)
    self._menubar_sep.pack(fill="x",expand="yes")

    self._pane = tk.Frame(self)
    self._pane.pack(fill="both",expand="yes")

    #label = tk.Label(self, text="")
    #self.default_font = tkFont.Font(font=label['font'])
    #label.destroy()
    #self.default_font.configure(size="10")
    ##self.default_font = tkFont.Font(family="Times", size="10")
    #print self.default_font.actual()

    self._clpbrd_menu = tk.Menu(self, tearoff=0)
    self._clpbrd_menu.add_command(label="Cut")
    self._clpbrd_menu.add_command(label="Copy")
    self._clpbrd_menu.add_command(label="Paste")
    def show_clpbrd_menu(e):
      w = e.widget
      edit_choice_state = "normal"
      try:
        if (w.cget("state") == "disabled"): edit_choice_state = "disabled"
      except (Exception) as err:
        pass
      self._clpbrd_menu.entryconfigure("Cut", command=lambda: w.event_generate("<<Cut>>"), state=edit_choice_state)
      self._clpbrd_menu.entryconfigure("Copy", command=lambda: w.event_generate("<<Copy>>"))
      self._clpbrd_menu.entryconfigure("Paste", command=lambda: w.event_generate("<<Paste>>"), state=edit_choice_state)
      self._clpbrd_menu.tk.call("tk_popup", self._clpbrd_menu, e.x_root, e.y_root)
    self.bind_class("Entry", "<Button-3><ButtonRelease-3>", show_clpbrd_menu)
    self.bind_class("Text", "<Button-3><ButtonRelease-3>", show_clpbrd_menu)
    #self.bind("<<EventEnqueued>>", self.process_event_queue)
    self.wm_protocol("WM_DELETE_WINDOW", self._on_delete)

    def poll_queue():
      self.process_event_queue(None)
      self._poll_queue_alarm_id = self.after(100, self._poll_queue)
    self._poll_queue_alarm_id = None
    self._poll_queue = poll_queue

    self.resizable(False, False)  # Stops user resizing.
    self.switch_to_splash()
    self._poll_queue()

  def switch_to_splash(self):
    self.remove_all()

    self.wm_title("TweetSubs %s" % self.VERSION)
    self.state["phase"] = self.PHASE_SPLASH
    self._update_menu_states()
    self.tmp_frame = tk.Frame(self._pane)
    self.tmp_frame.pack()

    warning_frame = tk.Frame(self.tmp_frame, borderwidth="1",relief="sunken")
    warning_frame.pack(fill="x",expand="yes",pady=("10","0"))

    warning_lbl = tk.Label(warning_frame, text="...")
    warning_lbl.pack(fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

  def switch_to_welcome(self, next_func):
    self.remove_all()

    self.wm_title("TweetSubs %s" % self.VERSION)
    self.state["phase"] = self.PHASE_WELCOME
    self._update_menu_states()
    self.tmp_frame = tk.Frame(self._pane)
    self.tmp_frame.pack()

    notice_str = ""
    notice_str += "This frontend will connect to Twitter, launch VLC, and\n"
    notice_str += "display live @tweets as subtitles over any video you watch.\n"
    notice_str += "\n"
    notice_str += "OR, if the video is not playable in VLC, commentary can be\n"
    notice_str += "sent to a window that can float over proprietary players.\n"
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

    warning_lbl = tk.Label(warning_frame, text="Note: Closing this window will kill VLC.")
    warning_lbl.pack(fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

    next_btn.bind(sequence="<Return>", func=next_btn["command"])
    next_btn.focus_set()

  def switch_to_pin_prompt(self, next_func, req_token, auth_url):
    self.remove_all()

    self.wm_title("TweetSubs - PIN")
    self.state["phase"] = self.PHASE_PIN
    self._update_menu_states()
    self.tmp_frame = tk.Frame(self._pane)
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

    self.wm_title("TweetSubs - Countdown")
    self.state["phase"] = self.PHASE_COUNTDOWN
    self._update_menu_states()
    self.tmp_frame = tk.Frame(self._pane)
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

    self.wm_title("TweetSubs - Follow")
    self.state["phase"] = self.PHASE_FOLLOW
    self._update_menu_states()
    self.tmp_frame = tk.Frame(self._pane)
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

    self.wm_title("TweetSubs - Compose (as %s)" % src_user_name)
    self.state["phase"] = self.PHASE_COMPOSE
    self._update_menu_states()
    self.tmp_frame = tk.Frame(self._pane)
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
    warning_frame.pack(fill="x",expand="yes",pady=("0","0"))

    warning_lbl = tk.Label(warning_frame, text="From the Options menu: pick VLC or Floating.")
    warning_lbl.pack(side="left",fill="x",expand="yes")
    self.state["warning_lbl"] = warning_lbl

    clock_sep = tk.Frame(warning_frame, border=1,relief="sunken")
    clock_sep.pack(side='left',fill='y',ipadx="1")
    #clock_sep = tk.Label(warning_frame, text="|")
    #clock_sep.pack(side="left",fill="y",expand="no")

    clock_lbl = tkwidgets.CountdownClock(warning_frame, target_time=countdown_to_time)
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
    """Toggles important widgets' enabled state, depending on the current phase."""
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
    """Removes self.tmp_frame from the window and resets it to None.
    The self.state dict is also cleared.
    """
    if (self.tmp_frame):
      self.tmp_frame.pack_forget()  # or grid_forget()
      self.tmp_frame.destroy()
      self.tmp_frame = None
    self.state.clear()

  def _update_menu_states(self):
    """Toggles menus' disabled states depending on phase.

    PHASE_COMPOSE: All menuitems with funcs are enabled.
    Otherwise: All menuitems are disabled.
    """
    state_matched = False
    if ("phase" in self.state):
      if (self.state["phase"] == self.PHASE_COMPOSE):
        state_matched = True
        for menu_label in [self.MENU_IGNORE_USERS, self.MENU_COMMENTARY, self.MENU_SPAWN_VLC]:
          if (menu_label not in self._menu_lookup): continue
          parent_menu = self._menu_lookup[menu_label]
          if (menu_label in self._menu_funcs and self._menu_funcs[menu_label] is not None):
            parent_menu.entryconfigure(menu_label, state="normal", command=self._menu_funcs[menu_label])
          else:
            parent_menu.entryconfigure(menu_label, state="disabled")

    if (state_matched is False):
      for menu_label in [self.MENU_IGNORE_USERS, self.MENU_COMMENTARY, self.MENU_SPAWN_VLC]:
        if (menu_label not in self._menu_lookup): continue
        parent_menu = self._menu_lookup[menu_label]
        parent_menu.entryconfigure(menu_label, state="disabled")

  def set_menu_callback(self, menu_label, func):
    """Associates a menuitem with a callback function, and toggles its disabled state.

    :param menu_label: One of the MENU_* constants.
    :param func: A no-arg function, or None.
    """
    if (menu_label not in self._menu_lookup or self._menu_lookup[menu_label] is None):
      logging.error("Attempted to set a callback on non-existent menuitem: %s." % menu_label)
      return

    self._menu_funcs[menu_label] = func
    self._update_menu_states()

  def center_window(self):
    """Centers this window on the screen.
    Mostly. Window manager decoration and the menubar aren't factored in.
    """
    # An event-driven call to this would go nuts with plain update().
    self.update_idletasks()  # Make window width/height methods work.
    xp = (self.winfo_screenwidth()//2) - (self.winfo_width()//2)
    yp = (self.winfo_screenheight()//2) - (self.winfo_height()//2)
    self.geometry("+%d+%d" % (xp, yp))

    # Geometry WxH+X+Y resizes, but any manual sizing disables auto-fit.
    #self.geometry("%dx%d+%d+%d" % (self.winfo_width(), self.winfo_height(), xp, yp))
    # To Auto-fit again, clear the geometry.
    #self.winfo_toplevel().wm_geometry("")

    # Misc notes...
    #self.pack_propagate(False)  # Tells a widget to ignore its contents' requests to resize.

  def set_topmost(self, b):
    """Toggles 'always on top' for this window. (Windows only)"""
    if (b is True): self.attributes('-topmost', 1)
    else: self.attributes('-topmost', 0)

  def _show_caption_window(self):
    """Shows the floating commentary window and toggles the menuitem."""
    if (self._caption_window is None):
      self.set_menu_callback(self.MENU_COMMENTARY, None)
      self._caption_window = tkwidgets.CaptionWindow(self, title="Floating Commentary - TweetSubs", delete_func=self._on_caption_window_deleted)
      self._caption_window.get_text_area().configure(foreground="white", background="black")

  def _on_caption_window_deleted(self):
    """Toggles the menuitem when the floating commentary window closes."""
    if (self._caption_window is not None):
      self._caption_window = None
      self.set_menu_callback(self.MENU_COMMENTARY, self._show_caption_window)

  def _on_delete(self):
    if (self._poll_queue_alarm_id is not None):
      self.after_cancel(self._poll_queue_alarm_id)
      self._root().quit()

  def process_event_queue(self, event):
    """Processes every pending event on the queue."""
    # With after() polling, always use get_nowait() to avoid blocking.
    func_or_name, arg_dict = None, None
    while (True):
      try:
        func_or_name, arg_dict = self._event_queue.get_nowait()
      except (Queue.Empty) as err:
        break
      else:
        self._process_event(func_or_name, arg_dict)

  def _process_event(self, func_or_name, arg_dict):
    """Processes events queued via invoke_later().

    ACTION_SWITCH_WELCOME(next_func)
    ACTION_SWITCH_PIN(next_func, req_token, auth_url)
    ACTION_SWITCH_COUNTDOWN(next_func)
    ACTION_SWITCH_FOLLOW(next_func)
    ACTION_SWITCH_COMPOSE(next_func, text_clean_func, max_length, src_user_name, countdown_to_time)
    ACTION_SWITCH_COMPOSE_NERFED(src_user_name, countdown_to_time)
    ACTION_COMPOSE_TEXT(text)
    ACTION_WARN(message)
    ACTION_NEW_TWEET(user_str, msg_str, tweet_json)
    ACTION_SETUP_IGNORE_USERS(get_all_users_func, get_ignored_users_func, set_ignored_users_func)
    ACTION_SETUP_SPAWN_VLC(spawn_func)
    ACTION_DIE
    """
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
    elif (func_or_name == self.ACTION_NEW_TWEET):
      if (check_args(["user_str","msg_str","tweet_json"])):
        if (self._caption_window is not None):
          self._caption_window.flash_message("%s: %s" % (arg_dict["user_str"], arg_dict["msg_str"]), global_config.osd_duration*1000)
    elif (func_or_name == self.ACTION_SETUP_IGNORE_USERS):
      if (check_args(["get_all_users_func","get_ignored_users_func","set_ignored_users_func"])):
        get_all_users_func = arg_dict["get_all_users_func"]
        get_ignored_users_func = arg_dict["get_ignored_users_func"]
        set_ignored_users_func = arg_dict["set_ignored_users_func"]

        if (get_all_users_func and get_ignored_users_func and set_ignored_users_func):
          def show_ignore_dialog():
            all_users = get_all_users_func()
            ignored_users = get_ignored_users_func()

            if (len(all_users) + len(ignored_users) == 0):
              self.invoke_later(self.ACTION_WARN, {"message":"No users to choose from. Try again later."})
              return

            current_ticks = {}
            for u in all_users:
              current_ticks[u] = 0
            for u in ignored_users:
              if (u not in current_ticks or current_ticks[u] == 0):
                current_ticks[u] = 1

            def ok_callback(new_ticks):
              new_ignored_users = [k for (k,v) in new_ticks.items() if (v == 1)]
              set_ignored_users_func(new_ignored_users)

            tkwidgets.CheckboxListDialog(self, title="Ignore Users", namelist=current_ticks, metacols=3, max_height=150, ok_func=ok_callback)
          self.set_menu_callback(self.MENU_IGNORE_USERS, show_ignore_dialog)
        else:
          self.set_menu_callback(self.MENU_IGNORE_USERS, None)
    elif (func_or_name == self.ACTION_SETUP_SPAWN_VLC):
      if (check_args(["spawn_func"])):
        spawn_func = arg_dict["spawn_func"]
        if (spawn_func):
          self.set_menu_callback(self.MENU_SPAWN_VLC, spawn_func)
        else:
          self.set_menu_callback(self.MENU_SPAWN_VLC, None)

    elif (func_or_name == self.ACTION_DIE):
      self._root().destroy()

  def invoke_later(self, func_or_name, arg_dict):
    """Schedules an action to occur in this thread (thread-safe)."""
    self._event_queue.put((func_or_name, arg_dict))
    # The queue will be polled eventually by an after() alarm.

    #try:
    #  self._event_queue.put((func_or_name, arg_dict))
    #  self.event_generate("<<EventEnqueued>>", when="tail")
    #  # Grr, event_generate from a non-GUI thread can raise RuntimeError.
    #  return True
    #except (tk.TclError) as err:
    #  # mainthread() is no longer running.
    #  return False
