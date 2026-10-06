' Windowless runner for the adaptive hosts pass (no console flash).
' Paths are derived from this script's own location, so it works from any clone dir.
Dim sh, dir, cmd
Set sh = CreateObject("WScript.Shell")
dir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
cmd = "node.exe """ & dir & "accel.mjs"""
sh.CurrentDirectory = dir
sh.Run cmd, 0, False
Set sh = Nothing
