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


class GuiApp(tk.Frame):
  """A tkinter GUI interface for TweetSubs.
  A separate thread handles logic and controls this widget via invoke_later().
  That thread provides callbacks, to later notify itself how the user responded.
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

    self.VERSION = global_config.VERSION

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

    self.pack()                        # Place self in parent.
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

    clock_lbl = tkwidgets.CountdownClock(warning_frame, text="+0:00:00", target_time=countdown_to_time)
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
