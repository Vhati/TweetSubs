from datetime import datetime, timedelta
import logging
import re
import Tkinter as tk


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
