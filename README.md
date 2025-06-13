Project Report: Security Investigation on Publicly Exposed Virtual Machines

1. Scenario Overview
During routine maintenance, the security team was tasked with investigating virtual machines (VMs) within the services cluster (responsible for DNS, domain services, DHCP, etc.) that were inadvertently exposed to the public internet. The goal of this investigation was to identify any misconfigured VMs and assess potential brute-force login attempts or successful compromises originating from external sources.

2. Hypothesis
Due to the accidental exposure of these virtual machines, there is a possibility that attackers may have attempted to gain unauthorized access through brute-force methods. Furthermore, older devices lacking account lockout policies for failed login attempts may have increased the risk of successful unauthorized logins.

3. Investigation Steps
3.1 Data Collection and Preparation

    Network and Endpoint Log Review:
    Logs were analyzed to determine which devices were publicly accessible and whether any login attempts were made.

    Device Exposure Confirmation:
    Querying the DeviceInfo table revealed that the device named ciprian-th-windows last connected to the internet on 2025-06-11T12:16:42.3509479Z and had been exposed for two days.

    DeviceInfo
    | where DeviceName contains "ciprian"
    | where IsInternetFacing == true
    | order by Timestamp desc
   
![1](https://github.com/user-attachments/assets/6c9fcdb4-a94d-404a-a426-485edd970c72)

3.2 Failed Login Attempts

    Login Failure Analysis:
    Multiple failed login attempts were identified from various accounts using the following query:

    DeviceLogonEvents
    | where DeviceName contains "ciprian"
    | where LogonType == "Network"
    | where ActionType == "LogonFailed"
    | summarize failed_logons = count() by DeviceName, RemoteIP, AccountName
    | order by failed_logons

    ![2](https://github.com/user-attachments/assets/c966fcee-775c-43f7-8449-bc4ceae6ab12)

    Suspicious Activity:
    One such attempt originated from the account scan using the IP address 92.53.65.234.
    
![3](https://github.com/user-attachments/assets/80da1a35-0020-40cd-944c-7a31135c5a9d)


3.3 Successful Login Attempts

    Verification of Successful Logins:
    No unauthorized successful login attempts were detected. The only successful login was performed by the legitimate account florinn:

DeviceLogonEvents
| where DeviceName contains "ciprian"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize count() by DeviceName, RemoteIP, AccountName
| order by count_

![5](https://github.com/user-attachments/assets/fba502c3-8413-47a3-8dc0-28a8ae4357a3)


Top 5 IPs With High Login Attempt Volume:

DeviceLogonEvents
| where DeviceName contains "ciprian"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where RemoteIP in ("94.26.229.189","45.92.176.178","77.223.121.121","45.92.177.247","82.202.197.36")

Florinn Account Validation:
The florinn user had no failed login attempts in the past 7 days:

DeviceLogonEvents
| where DeviceName contains "ciprian"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "florinn"
| summarize count()

Geolocation Consistency for Florinn:
The login IPs for the florinn user remained consistent, with no signs of abnormal access:

    DeviceLogonEvents
    | where DeviceName contains "ciprian"
    | where LogonType == "Network"
    | where ActionType == "LogonSuccess"
    | where AccountName == "florinn"
    | summarize login_count = count() by DeviceName, ActionType, AccountName, RemoteIP

    ![4](https://github.com/user-attachments/assets/0873f2c7-5840-4734-b4d2-bc85075a69e2)


4. Conclusion
Based on the investigation, it was confirmed that the exposed virtual machine did experience brute-force login attempts. However, no successful unauthorized access was detected. The only successful login was performed by a known and authorized account.

5. Mitigation and Remediation Measures

    The NSG (Network Security Group) rule that previously allowed internet exposure was deleted.

    A new rule was implemented to restrict RDP traffic solely to specific IP addresses.

6. Relevant Tactics, Techniques, and Procedures (TTPs)
    Tactic	                  Technique	                              MITRE ID(s)
    Reconnaissance	        Active Scanning	                            T1595
    Initial Access	        Brute Force (Guessing, Spraying)            T1110, T1110.001, T1110.003
    Discovery	            Account Discovery	                        T1087
    Defense Evasion	        Impair Defenses (Potentially)	            T1562
