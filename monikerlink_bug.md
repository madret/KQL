# Monikerlink bug
### Remote exploitation attempt of CVE-2024-21413 in outlook
```
DeviceProcessEvents
| where ProcessCommandLine contains "rundll32.exe C:\\WINDOWS\\system32\\davclnt.dll,DavSetCookie"
| where ProcessCommandLine contains "http" or ProcessCommandLine contains "https"
| where ProcessCommandLine matches regex @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
| where not (ProcessCommandLine contains "10." or ProcessCommandLine contains "172." or ProcessCommandLine contains "192.168")
| project-reorder Timestamp, AccountUpn, ProcessCommandLine, DeviceName
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort == "389"
    | where InitiatingProcessFileName == "OUTLOOK.EXE"
) on DeviceName
| project-reorder Timestamp, AccountUpn, ProcessCommandLine, DeviceName, RemotePort, InitiatingProcessFileName
```
