# Windows Security Event Monitoring

A collection of PowerShell scripts for analyzing Windows Security Event Logs and identifying common authentication and security activity.

## Scripts

### `Get-FailedLogins.ps1`
Detects failed Windows login attempts using **Event ID 4625**.

Displays:
- Timestamp
- Target username
- Source IP address
- Workstation name
- Failure reason
- Status code

```powershell
.\Get-FailedLogins.ps1 -Hours 24
```

---

### `Get-SuccessfulLogins.ps1`
Monitors successful Windows logins using **Event ID 4624**.

Displays:
- Timestamp
- Account
- Source IP
- Logon type

The script converts Windows logon type numbers into readable values such as Interactive, Network, Service, and RemoteInteractive (RDP).

```powershell
.\Get-SuccessfulLogins.ps1 -Hours 8
```

---

### `Get-PrivilegedLogins.ps1`
Identifies accounts receiving elevated privileges at login using **Event ID 4672**.

Displays:
- Timestamp
- Account
- Domain
- Privileges granted

Useful for monitoring administrative and privileged account activity.

```powershell
.\Get-PrivilegedLogins.ps1 -Hours 24
```

---

### `Find-BruteForceAttempts.ps1`
Detects possible brute-force login activity by analyzing repeated **Event ID 4625** failures.

The script groups failed login attempts by username and source IP and flags activity that exceeds a configurable threshold within a specified time window.

```powershell
.\Find-BruteForceAttempts.ps1 -Hours 24 -Threshold 5 -WindowMinutes 10
```

Example detection logic:

- Look back 24 hours
- Group failures by account and source IP
- Flag 5 or more failed attempts occurring within 10 minutes

## Requirements

- Windows
- PowerShell
- Access to the Windows Security Event Log
- Appropriate permissions to read Security logs

## Security Concepts Demonstrated

- Windows Event Log analysis
- Authentication monitoring
- Failed login detection
- Successful login auditing
- Privileged account monitoring
- Brute-force detection
- PowerShell automation
- Basic SOC detection logic

## Purpose

This project was created as a hands-on cybersecurity lab to practice using PowerShell for Windows security monitoring and SOC-style event analysis.

The scripts demonstrate how native Windows logs can be queried, parsed, and converted into useful security detections without requiring a full SIEM platform.

## Disclaimer

These scripts are intended for educational and defensive security purposes. They provide basic detection logic and are not intended to replace enterprise SIEM or endpoint detection solutions.
