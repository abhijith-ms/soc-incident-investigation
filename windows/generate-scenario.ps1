# Prepared for the isolated Windows lab; not executed during the fixture exercise.
whoami.exe
systeminfo.exe
$socLabText = "Write-Output 'SOC-LAB-P2'"
$socLabEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($socLabText))
powershell.exe -NoProfile -EncodedCommand $socLabEncoded
powershell.exe -NoProfile -Command "Write-Output 'SOC-LAB-P2'"
