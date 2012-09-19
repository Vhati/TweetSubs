import htmlentitydefs
import logging
import os
import re
import sys


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
