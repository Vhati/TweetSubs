TweetSubs
=========
A frontend to launch VLC, follow someone on Twitter, and display any live @tweets mentioning that account as subtitles in VLC.

Geographically separated people can schedule a video to play simultaneously, follow the same account, compose tweets, and see each other's commentary. (Example: [MockTM Events][http://twitter.com/MockTM])


Requirements
------------
Windows, Linux, or... possibly OSX (coded w/o a test box).

* Python 2.6 or higher, but not 3.x.
    * http://www.python.org/getit/
* VLC 2.x.x
    * http://www.videolan.org/vlc/
* Tk
    * Windows builds of Python include Tk.
    * Linux will need the python-tk package.
    * OSX may need to replace the stock Tcl/Tk from Apple.
        * http://www.python.org/download/mac/tcltk/
