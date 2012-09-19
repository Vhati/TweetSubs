import ctypes
import errno
import hashlib
import logging
import os
import platform
import re
import subprocess
import sys


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

  :param program: A filename to search for (with or without extension).
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
