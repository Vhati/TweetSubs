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


VERSION = "1.07"
INTF_LUA_NAME = "tweetsubs_cli.lua"  # VLC panics if this has a hyphen!?
CONSUMER_KEY = "y5Okw5ltA6PUe9H1uumA3w"
CONSUMER_SECRET = "a0r1x7fwbepzaxkaweafGU1Xrpfe6hDFfCnVToUbU"
