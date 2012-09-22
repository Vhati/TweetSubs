from datetime import datetime, timedelta
import logging
import re
import threading
import Tkinter as tk
import tkMessageBox


class CheckboxList(tk.Frame):
  def __init__(self, parent, *args, **kwargs):
    """Constructs a scrollable list of checkboxes.

    :param namelist: A dict of names and (0 or 1) values.
    :param metacols: The number of columns of options.
    """
    custom_args = {"namelist":{}, "metacols":3, "max_height":150}
    for k in custom_args.keys():
      if (k in kwargs):
        custom_args[k] = kwargs[k]
        del kwargs[k]
    tk.Frame.__init__(self, parent, *args, **kwargs)

    self.grid_rowconfigure(0, weight=1)
    self.grid_columnconfigure(0, weight=1)

    #self.xscrollbar = tk.Scrollbar(self, orient="horizontal")
    #self.xscrollbar.grid(row=1, column=0, sticky="ew")

    self.yscrollbar = tk.Scrollbar(self)
    self.yscrollbar.grid(row=0, column=1, sticky="ns")

    self.canvas = tk.Canvas(self, borderwidth=0)
    self.canvas.grid(row=0, column=0, sticky="nsew")

    #self.canvas.config(xscrollcommand=self.xscrollbar.set)
    self.canvas.config(yscrollcommand=self.yscrollbar.set)
    #self.xscrollbar.config(command=self.canvas.xview)
    self.yscrollbar.config(command=self.canvas.yview)

    table_frame = tk.Frame(self.canvas, padx=5, pady=10)
    metacols = custom_args["metacols"]
    metacol_span = 1
    self._ticks = {}  # Don't it get garbage collected before the widget.

    for metacol in range(metacols*metacol_span):
      table_frame.grid_columnconfigure(metacol+0, weight=0)

    for (i, (name, val)) in enumerate(sorted(custom_args["namelist"].items(), key=lambda (n,v): n.lower())):
      metacol = (i%metacols)*metacol_span
      self._ticks[name] = tk.IntVar()
      self._ticks[name].set(val)

      tmp_check = tk.Checkbutton(table_frame, text=name, variable=self._ticks[name])
      tmp_check.grid(row=(i//metacols), column=metacol+0, sticky="w")

    win_id = self.canvas.create_window(0,0, anchor="nw", window=table_frame)

    self.winfo_toplevel().update()  # calc bbox's.
    canvas_bbox = self.canvas.bbox("all")
    self.canvas.config(scrollregion=canvas_bbox, width=canvas_bbox[2])
    self.canvas.config(height=min(custom_args["max_height"], canvas_bbox[3]))
    #self.canvas.config(scrollregion=(0, 0, 1000, 1000))

  def get_values(self):
    """Returns a dict of names and (0 or 1) values."""
    return dict([(k, v.get()) for (k, v) in self._ticks.items()])


class CurrentTimeClock(tk.Label):
  """A clock widget that dynamically shows UTC time."""

  def __init__(self, parent, *args, **kwargs):
    tk.Label.__init__(self, parent, *args, **kwargs)
    self._prev_str = ""
    self._alarm_id = None
    self._tick()

  def _tick(self):
    current_time = datetime.utcnow()
    new_str = current_time.strftime("%H:%M:%S")
    if (new_str != self._prev_str):
      self._prev_str = new_str
      self.config(text=new_str)
    self._alarm_id = self.after(200, self._tick)  # Call again in 200 msec
    # If not cancelled when self is destroyed (Perl does cancel),
    # See self.after_cancel(self.alarm_id) to put in self._destroy()
    # destroy_id = widget.bind('<Destroy>', self._destroy)


class CountdownClock(tk.Label):
  """A clock widget that dynamically shows distance from a UTC datetime.
  If target_time is None, no countdown occurs.
  """

  def __init__(self, parent, *args, **kwargs):
    self.custom_args = {"target_time":None}
    for k in self.custom_args.keys():
      if (k in kwargs):
        self.custom_args[k] = kwargs[k]
        del kwargs[k]

    tk.Label.__init__(self, parent, *args, **kwargs)
    self._clock_lock = threading.RLock()
    self._target_time = None
    self._prev_str = ""
    self._alarm_id = None
    self.set_target_time(self.custom_args["target_time"])

  def set_target_time(self, utc_datetime):
    """Set the target time. (thread-safe)"""
    with self._clock_lock:
      if (self._alarm_id is not None): self.after_cancel(self._alarm_id)
      self._target_time = utc_datetime
      if (self._target_time is None):
        self._prev_str = "--:--:--"
        self.config(text=self._prev_str)
      else:
        self._tick()

  def _tick(self):
    with self._clock_lock:
      if (self._target_time is None):
        if (self._alarm_id is not None): self.after_cancel(self._alarm_id)
        return

      current_time = datetime.utcnow()
      diff_delta = current_time - self._target_time
      sign = ("+" if (abs(diff_delta) == diff_delta) else "-")
      hours, remainder = divmod(abs(diff_delta).seconds, 3600)
      minutes, seconds = divmod(remainder, 60)
      new_str = "%s%d:%02d:%02d" % (sign, hours, minutes, seconds)
      if (new_str != self._prev_str):
        self._prev_str = new_str
        self.config(text=new_str)
      self._alarm_id = self.after(200, self._tick)  # Call again in 200 msec

  def config(self, *args, **kwargs):
    for k in self.custom_args.keys():
      if (k in kwargs):
        self.custom_args[k] = kwargs[k]
        del kwargs[k]
        if (k == "target_time"):
          self.set_target_time(self.custom_args["target_time"])
    tk.Label.config(self, *args, **kwargs)


class CenteredDialog(tk.Toplevel):
  """A base class for modal popup windows.
  Based on tkSimpleDialog.Dialog, ignoring
  platform-specific bits.

  See: http://wiki.tcl.tk/10013
  """

  def __init__(self, parent, title=None):
    tk.Toplevel.__init__(self, parent)

    if (parent.winfo_viewable()): self.transient(parent)
    if (title): self.title(title)

    self.parent = parent
    self.result = None

    body = tk.Frame(self)
    self.initial_focus = self.body(body)
    body.pack(padx=5, pady=5)

    self.buttonbox()

    # Visibility events don't fire on non-X11 platforms.
    # self.wait_visibility()
    while (True):
      try:
        self.grab_set()
      except (tk.TclError) as err:
        time.sleep(0.05)  # Not yet visible.
      else:
        break

    if (not self.initial_focus): self.initial_focus = self

    self.protocol("WM_DELETE_WINDOW", self.cancel)

    #self.update_idletasks()  # Not needed for reqwidth/reqheight?
    self_w = self.winfo_reqwidth()
    self_h = self.winfo_reqheight()
    self_x = self.winfo_screenwidth()//2 - self_w//2
    self_y = self.winfo_screenheight()//2 - self_h//2
    if (parent is not None):
      self_x = parent.winfo_rootx() + parent.winfo_reqwidth()//2 - self_w//2
      self_y = parent.winfo_rooty() + parent.winfo_reqheight()//2 - self_h//2
    if (self_x+self_w > self.winfo_screenwidth()):
      self_x = self.winfo_screenwidth() - self_w
    self_x = max(self_x, 0)
    if (self_y+self_h > self.winfo_screenheight()):
      self_y = self.winfo_screenheight() - self_h
    self_y = max(self_y, 0)
    self.geometry("+%d+%d" % (self_x, self_y))

    self.initial_focus.focus_set()
    self.wait_window(self)  # This'll pause the function that
                            # created this until closing, but
                            # without grab_set, other windows
                            # will still be responsive.

  def destroy(self):
    """Destroy the window."""
    self.initial_focus = None
    tk.Toplevel.destroy(self)

  def body(self, master):
    """Adds widgets to the dialog. (Called by init.)
    This should be overridden.

    :param master: The master for the new widgets.
    :returns: A widget to initially focus, or None.
    """

  def buttonbox(self):
    """Adds OK/Cancel buttons to the dialog.
    Override for different buttons.
    """
    box = tk.Frame(self)

    w = tk.Button(box, text="OK", width=10, command=self.ok, default="active")
    w.pack(side="left", padx=5, pady=5)
    w = tk.Button(box, text="Cancel", width=10, command=self.cancel)
    w.pack(side="left", padx=5, pady=5)

    self.bind("<Return>", self.ok)
    self.bind("<Escape>", self.cancel)

    box.pack()

  def ok(self, event=None):
    if (not self.validate()):
      self.initial_focus.focus_set()  # Refocus.
      return

    self.withdraw()
    self.update_idletasks()

    try:
      self.apply()
    finally:
      self.cancel()

  def cancel(self, event=None):
    """Refocuses the parent window and destroys this dialog."""
    if (self.parent is not None): self.parent.focus_set()
    self.destroy()

  def validate(self):
    """Checks whether this dialog is satisfied.
    This should be overridden, to set self.result.

    :returns: True if user response was acceptable. False to linger.
    """
    return True

  def apply(self):
    """Acts on self.result.
    This should be overridden.
    """
    pass


class CheckboxListDialog(CenteredDialog):
  def __init__(self, parent, *args, **kwargs):
    """Constructs a popup window containing a list of checkboxes.

    :param title: Window title (passed to superclass).
    :param namelist: A dict of names and (0 or 1) values.
    :param metacols: The number of columns of options.
    :param max_height: Maximum height of the list's visible area.
    :param ok_func: A callback that takes the result of CheckboxList.get_values(), when OK is clicked.
    """
    self.custom_args = {"namelist":{}, "metacols":3, "max_height":150, "ok_func":None}
    for k in self.custom_args.keys():
      if (k in kwargs):
        self.custom_args[k] = kwargs[k]
        del kwargs[k]
    CenteredDialog.__init__(self, parent, *args, **kwargs)

  def body(self, master):
    """Adds widgets to the dialog. (Called by init.)"""
    namelist = self.custom_args["namelist"]
    metacols = self.custom_args["metacols"]
    max_height = self.custom_args["max_height"]
    self.checks_grid = CheckboxList(master, borderwidth=2,relief="sunken", namelist=namelist, metacols=metacols, max_height=max_height)
    self.checks_grid.pack(fill="both",expand="yes")

    focus_widget = None
    return focus_widget

  def validate(self):
    """Checks whether this dialog is satisfied and sets self.result.

    :returns: True if user response was acceptable. False to linger.
    """
    self.result = self.checks_grid.get_values()
    return True

  def apply(self):
    """Acts on self.result."""
    if (self.custom_args["ok_func"] is not None):
      self.custom_args["ok_func"](self.result)
    else:
      print repr(self.result)
