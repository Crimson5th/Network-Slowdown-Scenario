# Network-Slowdown-Scenario
Sudden Network Slowdowns Scenario

1. Preparation
● Goal: Set up the hunt by defining what you're looking for.

● Activity: Develop a hypothesis based on threat intelligence and security gaps (e.g.,
“Could there be lateral movement in the network?”).

3. Data Collection
● Goal: Gather relevant data from logs, network traffic, and endpoints.

● Activity: Ensure data is available from all key sources for analysis.


5. Data Analysis
● Goal: Analyze data to test your hypothesis.

● Activity: Look for anomalies, patterns, or indicators of compromise (IOCs) using various
tools and techniques.


7. Investigation
● Goal: Investigate any suspicious findings.

● Activity: Dig deeper into detected threats, determine their scope, and escalate if
necessary. See if anything you find matches TTPs within the MITRE ATT&CK
Framework.


9. Response
● Goal: Mitigate any confirmed threats.

● Activity: Work with security teams to contain, remove, and recover from the threat

11. Documentation
● Goal: Record your findings and learn from them.

● Activity: Document what you found and use it to improve future hunts and defenses.


13. Improvement
● Goal: Improve your security posture or refine your methods for the next hunt.

● Activity: Adjust strategies and tools based on what worked or didn’t.


Notes / Findings:


Timeline Summary and Findings:


Windows-target-1 was found failing several connection requests against itself and another host on the samenetwork:

DeviceNetworkEvents


| where ActionType == "ConnectionFailed"


| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP


| order by ConnectionCount


![NetSlo](https://github.com/user-attachments/assets/d41dcc5b-4cf1-4e5d-9e73-6cbef1dc0081)


---------------

After observing failed log activity from the suspected host (10.0.0.5) in chronological order. I noticed a port scan was taking place 
due to the sequential order of the ports.There were several port scans being conducted:

let IPInQuestion = "10.0.0.5";


DeviceNetworkEvents


| where ActionType == "ConnectionFailed"


| where LocalIP == IPInQuestion


| order by Timestamp desc


![NetSloo](https://github.com/user-attachments/assets/0db59982-7d02-441f-8a54-f80f5a3b0a02)


--------------

I pivoted to the DeviceProcessEvents table to see if I could see anything that was suspicious around the time the port scan started. 
I noticed a Powershell script named portscan.ps1 lauch at 2025-03-24T12:38:00.4864878Z

let VMName = "windows-target-1";


let specificTime = datetime(2025-03-24T12:38:38.5802941Z);


DeviceProcessEvents


| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))


| where DeviceName == VMName


| order by Timestamp desc


| project Timestamp, FileName, InitiatingProcessCommandLine


--------------

I logged into the suspect computer and observed the powershell that was used to conduct the port scan:

------------

I observed the port scan script was lauched by the SYSTEM account, this is not expected behavoir and is not something that was setup by the admins
so I isolated the device and ran an malware scan.

---------

The malware scan produced no results so out of caution we kept the device isolated and put in a ticket to have it reimage/rebuilt 

