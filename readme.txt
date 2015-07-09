TweetSubs v1.07

Author:
  David Millis (tvtronix@yahoo.com)


About

  A frontend to launch VLC, follow someone on Twitter,
and display any live @tweets mentioning that account as
subtitles in VLC.

  Geographically separated people can schedule a video to
play simultaneously, follow the same account, compose tweets,
and see each other's commentary.
( Example: MockTM Events http://twitter.com/MockTM )

  Alternatively, if the video isn't playable in VLC,
commentary can be sent to a window that can float over
proprietary players.



Usage

Double-click tweetsubs.py
(To hide the debugging console, rename it to .pyw)
(Linux and OSX should set permissions to make it executable)
OR
From a terminal, run: python tweetsubs.py



Troubleshooting

If you're running Linux from a livecd or usb drive, and you
get a 401 Unauthorized error while fetching an auth request
token from Twitter... You may need to set your local
timezone in the OS's preferences.



Changes

1.06 - Switched to Twitter 1.1 API.
1.05 - Added "Ignore Users" option.
       Added "Floating Commentary" window.
       Fixed Twitter user lookup (they changed their API a little).
       Moved various classes and functions to their own lib modules.
1.04 - Trivially changed negative millisecond lag notice to "0s" instead of "-0s".
1.03 - Added a reconnect prompt when the followed Twitter stream disconnects.
       Moved Twitter client classes into a separate lib module.
1.02 - Softened the minute lag notice after a field test yielded zero lag.
       Added keyboard shortcut to compose panel: return-to-send (shift-return adds newlines).
       Added an apostrophe variant to asciify().
       Shrank the compose panel by moving the "Tweeting as..." reminder to the title bar.
       Added a 70 sec timeout if the follow/sample stream goes silent (not even keep-alive \r\n's).
       Code cleanup.
1.01 - Fixed mislocated data dirs on Linux.
       Adjusted logging to report when tk is missing.
1.00 - Initial release.



Requirements

Windows, Linux, or... possibly OSX (coded w/o a test box).

Python 2.6 or higher, but not 3.x.
  http://www.python.org/getit/
VLC 2.x.x
  http://www.videolan.org/vlc/

* Linux will need the python-tk package.
* OSX may need to replace the stock Tcl/Tk from Apple.
  http://www.python.org/download/mac/tcltk/



Sources

oauth.py (modified from r1267)  https://code.google.com/p/oauth/
cli.lua  (2.0.1)                From VLC source code.
