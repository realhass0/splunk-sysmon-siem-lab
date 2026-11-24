# Windows Endpoint & SIEM Lab (Splunk + Sysmon)

I built this lab on my Windows 11 machine (`DESKTOP-O1L1JB0`) to practice ingesting raw endpoint telemetry, writing SPL detection queries, and tuning real-time alerts without spinning up a heavy multi-VM stack.

## Setup
* **Host:** Windows 11 (`DESKTOP-O1L1JB0`)
* **Endpoint Agent:** Sysmon v15.22 running the SwiftOnSecurity config
* **SIEM:** Splunk Enterprise ingesting `WinEventLog:Security` and `Microsoft-Windows-Sysmon/Operational`

I configured Splunk's `inputs.conf` with `renderXml = true` for the Sysmon channel so every process creation (`EventID 1`) and network connection (`EventID 3`) came through with full command-line arguments and parent process context. Because Sysmon renders fields as nested XML attributes (`<Data Name='Image'>`), standard key-value extraction didn't pull the fields cleanly on its own, so I used inline `rex` extractions in my queries.

---

## Test 1: SMB Network Brute-Force (T1110.001)

To simulate password guessing against a local account, I ran a PowerShell loop attempting 6 rapid SMB network logons (`net use \\127.0.0.1\IPC$`) against my local `ansha` account with wrong passwords.

**Query used:**
```spl
source="WinEventLog:Security" EventCode=4625 Logon_Type=3 
| stats count by Account_Name, Source_Network_Address, Sub_Status
