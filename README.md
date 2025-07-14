# 🛡️ Azure Sentinel Threat Detection & Response Lab

This project demonstrates a hands-on, end-to-end **Security Operations Center (SOC)** simulation using **Microsoft Sentinel** on Azure. It involves:
- Ingesting security telemetry from a Windows Server VM
- Simulating real-world cyberattacks (e.g., brute force, PowerShell misuse)
- Writing KQL-based detection rules
- Automating incident response via a Logic App playbook

---

## 🧰 Tools & Technologies Used

| Tool | Purpose |
|------|---------|
| **Azure Sentinel** | Cloud-native SIEM for threat detection and response |
| **Log Analytics Workspace (LAW)** | Stores security data from connected resources |
| **Azure Virtual Machine (Windows Server 2022)** | Host for attack simulations |
| **Kusto Query Language (KQL)** | For log analysis and detection rules |
| **Azure Logic Apps** | Automates incident response |
| **Microsoft Defender for Cloud** | Security recommendations and alerts |

---

## 🔌 Data Connectors Configured

The following built-in connectors were configured in Microsoft Sentinel:

- `Security Events` (for Windows VM)
- `Azure Activity` (optional)
- `Heartbeat` (monitoring agent availability)

These connectors ensure logs such as **Event ID 4625** (Failed Logon) and **Event ID 4688** (New Process Created) are forwarded to Sentinel for analysis.

---

## 💥 Attack Simulations Performed

| Scenario | Technique | Triggered Event ID |
|----------|-----------|--------------------|
| RDP Brute Force | 10+ failed login attempts via RDP | 4625 |
| PowerShell Execution | `Invoke-WebRequest` to simulate malware download | 4688 |
| Registry Persistence | Registry edit using PowerShell | 4657 (if auditing enabled) |

All attacks were executed from within or toward the Azure VM and were successfully **logged, analyzed, and responded to**.

---

## 📊 Analytics Rule Used

Custom scheduled rule created in Sentinel:

**Name**: `Brute Force Detection`

**Query** ([See Full Query](./kql-queries/bruteforce.kql)):
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
