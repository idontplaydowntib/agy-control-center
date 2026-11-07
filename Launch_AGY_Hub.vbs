Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
DirPath = FSO.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = DirPath
WshShell.Run "pythonw.exe """ & DirPath & "\agy_hub.py""", 0, False
