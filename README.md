# Real-Time Detection System Against Malicious Tools by Monitoring DLL on Client Computers
These are tools for helping to detect execution of mimikatz using Sysmon logs.
We focus on dlls loaded by China Chopper, Mimikatz, PowerShell Empire and HUC Packet Transmitter.
Our related research is the following.

<a href="https://hitcon.org/2017/CMT/agenda" target="blank">HITCON Community 2017 DAY 2 (8/26): Tracking mimikatz by Sysmon and Elasticsearch</a>.


We provide the DLL List for each malicious tool.

https://github.com/sisoc-tokyo/attackToolDetection_Sysmon/tree/master/CommonDLLlist

We provide the following tools.
- A tool to create Common DLL List from exported event logs and detect processes that matches the Common DLL List (Java)<br/>
https://github.com/sisoc-tokyo/attackToolDetection_Sysmon/blob/master/tools/sysmon_detect/src/logparse/SysmonParser.java

- A tool to detect malicious tools China Chopper, Mimikatz, PowerShell Empire and HUC Packet Transmitter using the Common DLL Lists (Java)<br/>
https://github.com/sisoc-tokyo/attackToolDetection_Sysmon/blob/master/tools/sysmon_detect/src/logparse/SysmonDetecter.java


- A tool to detect processes that matches Common DLL List from Elasticsearch results (Python 3)

https://github.com/sisoc-tokyo/attackToolDetection_Sysmon/blob/master/tools/realtime-detection/

Before using our tools, you should procees the following steps.

- Install sysmon and gather event logs on the computer which you want to investigate.
  Please make sure that Event Id 7:Image loaded are recorded.

- To know the details of tools, please refer README for each tool.

Published by
Wataru Matsuda & Mariko Fujimoto