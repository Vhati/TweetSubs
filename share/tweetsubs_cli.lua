--[==========================================================================[
 tweetsubs-cli.lua: CLI module for VLC
--[==========================================================================[
 Copyright (C) 2012 David Millis

 Authors: David Millis (modified cli.lua from VLC 2.0.1)

See license.txt for the GNU GENERAL PUBLIC LICENSE
--]==========================================================================]

description=
[============================================================================[
 TweetSubs Command Line Interface for VLC

 This is a modules/control/rc.c look alike (with a bunch of new features).

 Use on local term:
    vlc -I cli
 Use on tcp connection:
    vlc -I cli --lua-config "cli={host='localhost:4212'}"
 Use on telnet connection:
    vlc -I cli --lua-config "cli={host='telnet://localhost:4212'}"
 Use on multiple hosts (term + plain tcp port + telnet):
    vlc -I cli --lua-config "cli={hosts={'*console','localhost:4212','telnet://localhost:5678'}}"

 Note:
    -I cli and -I luacli are aliases for -I luaintf --lua-intf cli

 Configuration options setable throught the --lua-config option are:
    * hosts: A list of hosts to listen on.
    * host: A host to listen on. (won't be used if 'hosts' is set)
    * password: The password used for telnet clients.
 The following can be set using the --lua-config option or in the interface
 itself using the 'set' command:
    * prompt: The prompt.
    * welcome: The welcome message.
    * width: The default terminal width (used to format text).
    * autocompletion: When issuing an unknown command, print a list of
                      possible commands to autocomplete with. (0 to disable,
                      1 to enable).
    * autoalias: If autocompletion returns only one possibility, use it
                 (0 to disable, 1 to enable).
    * osd_duration: Duration to show each OSD message (seconds).
]============================================================================]

require("common")

-- Do not edit.
osd_channel = -1


skip = common.skip
skip2 = function(foo) return skip(skip(foo)) end
setarg = common.setarg
strip = common.strip

_ = vlc.gettext._
N_ = vlc.gettext.N_

--[[ Setup default environment ]]
env = { prompt = "> ";
        width = 70;
        autocompletion = 1;
        autoalias = 1;
        welcome = _("Command Line Interface initialized. Type 'help' for help.");
        osd_duration = 6;
      }

--[[ Import custom environment variables from the command line config (if possible) ]]
for k,v in pairs(env) do
    if config[k] then
        if type(env[k]) == type(config[k]) then
            env[k] = config[k]
            vlc.msg.dbg("set environment variable '"..k.."' to "..tostring(env[k]))
        else
            vlc.msg.err("environment variable '"..k.."' should be of type "..type(env[k])..". config value will be discarded.")
        end
    end
end

--[[ Command functions ]]
function set_env(name,client,value)
    if value then
        local var,val = split_input(value)
        if val then
            local s = string.gsub(val,"\"(.*)\"","%1")
            if type(client.env[var])==type(1) then
                client.env[var] = tonumber(s)
            else
                client.env[var] = s
            end
        else
            client:append( tostring(client.env[var]) )
        end
    else
        for e,v in common.pairs_sorted(client.env) do
            client:append(e.."="..v)
        end
    end
end

function save_env(name,client,value)
    env = common.table_copy(client.env)
end

function logout(name,client)
    if client.type == host.client_type.net
    or client.type == host.client_type.telnet then
        client:send("Bye-bye!\r\n")
        client:del()
    else
        client:append("Error: Can't logout of stdin/stdout. Use quit or shutdown to close VLC.")
    end
end

function shutdown(name,client)
    client:append("Bye-bye!")
    h:broadcast("Shutting down.\r\n")
    vlc.msg.info("Requested shutdown.")
    vlc.misc.quit()
end

function quit(name,client)
    if client.type == host.client_type.net
    or client.type == host.client_type.telnet then
        logout(name,client)
    else
        shutdown(name,client)
    end
end

function help(name,client,arg)
    local width = client.env.width
    local long = (name == "longhelp")
    local extra = ""
    if arg then extra = "matching '" .. arg .. "' " end
    client:append("+----[ CLI commands "..extra.."]")
    for i, cmd in ipairs(commands_ordered) do
        if (cmd == "" or not commands[cmd].adv or long)
        and (not arg or string.match(cmd,arg)) then
            local str = "| " .. cmd
            if cmd ~= "" then
                local val = commands[cmd]
                if val.aliases then
                    for _,a in ipairs(val.aliases) do
                        str = str .. ", " .. a
                    end
                end
                if val.args then str = str .. " " .. val.args end
                if #str%2 == 1 then str = str .. " " end
                str = str .. string.rep(" .",(width-(#str+#val.help)-1)/2)
                str = str .. string.rep(" ",width-#str-#val.help) .. val.help
            end
            client:append(str)
        end
    end
    client:append("+----[ end of help ]")
end

function is_playing(name,client)
    if vlc.input.is_playing() then client:append "1" else client:append "0" end
end

function osd_message(name,client,message)
    local input = vlc.object.input()
    if not input or not vlc.object.vout() then return end

    -- Registration requires a video input.
    --   But apparently no need to re-register each new input.

    if osd_channel == -1 then
      osd_channel = vlc.osd.channel_register()
    end
    message = string.gsub(message, "\\n", "\n")
    vlc.osd.message(message, osd_channel, "bottom", client.env.osd_duration*1000000)
end

--[[ Declare commands, register their callback functions and provide
     help strings here.
     Syntax is:
     "<command name>"; { func = <function>; [ args = "<str>"; ] help = "<str>"; [ adv = <bool>; ] [ aliases = { ["<str>";]* }; ] }
     ]]
commands_ordered = {
    { "osd_msg"; { func = osd_message; args = "[message]"; help = "show OSD message" } };
    { "" };
    { "play"; { func = skip2(vlc.playlist.play); help = "play stream" } };
    { "is_playing"; { func = is_playing; help = "1 if a stream plays, 0 otherwise" } };
    { "" };
    { "set"; { func = set_env; args = "[var [value]]"; help = "set/get env var"; adv = true } };
    { "save_env"; { func = save_env; help = "save env vars (for future clients)"; adv = true } };
    { "help"; { func = help; args = "[pattern]"; help = "a help message"; aliases = { "?" } } };
    { "longhelp"; { func = help; args = "[pattern]"; help = "a longer help message" } };
    { "logout"; { func = logout; help = "exit (if in a socket connection)" } };
    { "quit"; { func = quit; help = "quit VLC (or logout if in a socket connection)" } };
    { "shutdown"; { func = shutdown; help = "shutdown VLC" } };
    }

commands = {}
for i, cmd in ipairs( commands_ordered ) do
    if #cmd == 2 then
        commands[cmd[1]]=cmd[2]
        if cmd[2].aliases then
            for _,a in ipairs(cmd[2].aliases) do
                commands[a]=cmd[1]
            end
        end
    end
    commands_ordered[i]=cmd[1]
end
--[[ From now on commands_ordered is a list of the different command names
     and commands is a associative array indexed by the command name. ]]

-- Compute the column width used when printing a the autocompletion list
env.colwidth = 0
for c,_ in pairs(commands) do
    if #c > env.colwidth then env.colwidth = #c end
end
env.coldwidth = env.colwidth + 1

--[[ Utils ]]
function split_input(input)
    local input = strip(input)
    local s = string.find(input," ")
    if s then
        return string.sub(input,0,s-1), strip(string.sub(input,s))
    else
        return input
    end
end

--[[ Command dispatch ]]
function call_command(cmd,client,arg)
    if type(commands[cmd]) == type("") then
        cmd = commands[cmd]
    end
    local ok, msg
    if arg ~= nil then
        ok, msg = pcall( commands[cmd].func, cmd, client, arg )
    else
        ok, msg = pcall( commands[cmd].func, cmd, client )
    end
    if not ok then
        local a = arg and " "..arg or ""
        client:append("Error in '"..cmd..a.."' ".. msg)
    end
end

function call_libvlc_command(cmd,client,arg)
    local ok, vlcerr = pcall( vlc.var.libvlc_command, cmd, arg )
    if not ok then
        local a = arg and " "..arg or ""
        client:append("Error in '"..cmd..a.."' ".. vlcerr) -- when pcall fails, the 2nd arg is the error message.
    end
    return vlcerr
end

function call_object_command(cmd,client,arg)
    local var, val
    if arg ~= nil then
        var, val = split_input(arg)
    end
    local ok, vlcmsg, vlcerr = pcall( vlc.var.command, cmd, var, val )
    if not ok then
        local v = var and " "..var or ""
        local v2 = val and " "..val or ""
        client:append("Error in '"..cmd..v..v2.."' ".. vlcmsg) -- when pcall fails the 2nd arg is the error message
    end
    if vlcmsg ~= "" then
        client:append(vlcmsg)
    end
    return vlcerr
end

function client_command( client )
    local cmd,arg = split_input(client.buffer)
    client.buffer = ""

    if commands[cmd] then
        call_command(cmd,client,arg)
    elseif string.sub(cmd,0,1)=='@' and call_object_command(string.sub(cmd,2,#cmd),client,arg) == 0 then
        --
    elseif client.type == host.client_type.stdio
    and call_libvlc_command(cmd,client,arg) == 0 then
        --
    else
        local choices = {}
        if client.env.autocompletion ~= 0 then
            for v,_ in common.pairs_sorted(commands) do
                if string.sub(v,0,#cmd)==cmd then
                    table.insert(choices, v)
                end
            end
        end
        if #choices == 1 and client.env.autoalias ~= 0 then
            -- client:append("Aliasing to \""..choices[1].."\".")
            cmd = choices[1]
            call_command(cmd,client,arg)
        else
            client:append("Unknown command '"..cmd.."'. Type 'help' for help.")
            if #choices ~= 0 then
                client:append("Possible choices are:")
                local cols = math.floor(client.env.width/(client.env.colwidth+1))
                local fmt = "%-"..client.env.colwidth.."s"
                for i = 1, #choices do
                    choices[i] = string.format(fmt,choices[i])
                end
                for i = 1, #choices, cols do
                    local j = i + cols - 1
                    if j > #choices then j = #choices end
                    client:append("  "..table.concat(choices," ",i,j))
                end
            end
        end
    end
end

--[[ Some telnet command special characters ]]
WILL = "\251" -- Indicates the desire to begin performing, or confirmation that you are now performing, the indicated option.
WONT = "\252" -- Indicates the refusal to perform, or continue performing, the indicated option.
DO   = "\253" -- Indicates the request that the other party perform, or confirmation that you are expecting the other party to perform, the indicated option.
DONT = "\254" -- Indicates the demand that the other party stop performing, or confirmation that you are no longer expecting the other party to perform, the indicated option.
IAC  = "\255" -- Interpret as command

ECHO = "\001"

function telnet_commands( client )
    -- remove telnet command replies from the client's data
    client.buffer = string.gsub( client.buffer, IAC.."["..DO..DONT..WILL..WONT.."].", "" )
end

--[[ Client status change callbacks ]]
function on_password( client )
    client.env = common.table_copy( env )
    if client.type == host.client_type.telnet then
        client:send( "Password: " ..IAC..WILL..ECHO )
    else
        if client.env.welcome ~= "" then
            client:send( client.env.welcome .. "\r\n")
        end
        client:switch_status( host.status.read )
    end
end
-- Print prompt when switching a client's status to 'read'
function on_read( client )
    client:send( client.env.prompt )
end
function on_write( client )
end

--[[ Setup host ]]
require("host")
h = host.host()

h.status_callbacks[host.status.password] = on_password
h.status_callbacks[host.status.read] = on_read
h.status_callbacks[host.status.write] = on_write

h:listen( config.hosts or config.host or "*console" )
password = config.password or "admin"

--[[ The main loop ]]
while not vlc.misc.should_die() do
    local write, read = h:accept_and_select()

    for _, client in pairs(write) do
        local len = client:send()
        client.buffer = string.sub(client.buffer,len+1)
        if client.buffer == "" then client:switch_status(host.status.read) end
    end

    for _, client in pairs(read) do
        local input = client:recv(1000)

        if input == nil -- the telnet client program has left
            or ((client.type == host.client_type.net
                 or client.type == host.client_type.telnet)
                and input == "\004") then
            -- Caught a ^D
            client.cmds = "quit\n"
        else
            client.cmds = client.cmds .. input
        end

        client.buffer = ""
        -- split the command at the first '\n'
        while string.find(client.cmds, "\n") do
            -- save the buffer to send to the client
            local saved_buffer = client.buffer

            -- get the next command
            local index = string.find(client.cmds, "\n")
            client.buffer = strip(string.sub(client.cmds, 0, index - 1))
            client.cmds = string.sub(client.cmds, index + 1)

            -- Remove telnet commands from the command line
            if client.type == host.client_type.telnet then
                telnet_commands( client )
            end

            -- Run the command
            if client.status == host.status.password then
                if client.buffer == password then
                    client:send( IAC..WONT..ECHO.."\r\nWelcome, Master\r\n" )
                    client.buffer = ""
                    client:switch_status( host.status.write )
                elseif client.buffer == "quit" then
                    client_command( client )
                else
                    client:send( "\r\nWrong password\r\nPassword: " )
                    client.buffer = ""
                end
            else
                client:switch_status( host.status.write )
                client_command( client )
            end
            client.buffer = saved_buffer .. client.buffer
        end
    end
end

--[[ Clean up ]]
