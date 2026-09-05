Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
scriptDir = files.GetParentFolderName(WScript.ScriptFullName)
pythonExe = files.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")
appScript = files.BuildPath(scriptDir, "login_guard.py")

If Not files.FileExists(pythonExe) Then
    WScript.Quit 1
End If

shell.CurrentDirectory = scriptDir
shell.Run Chr(34) & pythonExe & Chr(34) & " " & Chr(34) & appScript & Chr(34), 0, False
