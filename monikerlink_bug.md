# Monikerlink bug
### Detection of a remote exploitation attempt of CVE-2024-21413 in outlook
```
DeviceProcessEvents
| where ProcessCommandLine contains "rundll32.exe C:\\WINDOWS\\system32\\davclnt.dll,DavSetCookie"
| where ProcessCommandLine contains "http" or ProcessCommandLine contains "https"
| where ProcessCommandLine matches regex @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
| where not (ProcessCommandLine contains "10." or ProcessCommandLine contains "172." or ProcessCommandLine contains "192.168")
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort == "389"
    | where InitiatingProcessFileName == "OUTLOOK.EXE"
) on DeviceName
| project-reorder Timestamp, AccountUpn, ProcessCommandLine, DeviceName, RemotePort, InitiatingProcessFileName
```

#### Detection query on KQLSearch: 
https://github.com/ugurkocde/kql_search_submissions/blob/main/Outlook%20monikerlink%20zeroday.kql
