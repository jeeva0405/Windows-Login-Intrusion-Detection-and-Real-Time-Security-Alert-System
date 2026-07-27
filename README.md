<div align="center">



[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Windows](https://img.shields.io/badge/Windows-Event%20Log%204625-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://microsoft.com)
[![WinSW](https://img.shields.io/badge/WinSW-Background%20Service-4A154B?style=for-the-badge&logo=windows-terminal&logoColor=white)](https://github.com/winsw/winsw)
[![Jakarta Mail](https://img.shields.io/badge/Jakarta%20Mail-SMTP%20Alerts-00599C?style=for-the-badge&logo=gmail&logoColor=white)](https://jakarta.ee)
[![JUnit 5](https://img.shields.io/badge/JUnit%205-100%25%20Tested-25A162?style=for-the-badge&logo=junit5&logoColor=white)](https://junit.org/junit5/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

<br/>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=1000&color=E94560&center=true&vCenter=true&width=750&lines=Real-time+failed+login+detection+(Event+ID+4625);Automatic+background+Windows+Service+execution;Instant+HTML+security+email+alerts+to+system+owner;Webcam+evidence+snapshot+capture;Zero+secrets+in+code+%E2%80%94+env-driven+security" alt="Typing SVG" />
</p>

</div>

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Smilies/Star-Struck.png" alt="Star-Struck" width="25" height="25" /> Features

1. **Automatic Background Execution**: Runs as a silent background Windows Service on system startup using WinSW (Windows Service Wrapper).
2. **Real-Time Failed Login Detection**: Instantly identifies Event ID 4625 when an incorrect password is entered at the lock screen, RDP session, or network login.
3. **Duplicate Event Prevention**: Maintains persistent state (`config/state.properties`) recording the last processed `EventRecordID` to ensure each failed attempt triggers **exactly one** email alert.
4. **Rich HTML & Text Email Alerts**: Dispatches security emails containing formatted incident tables, logon type explanations, failure reason descriptions, and device details via Jakarta Mail & SMTP.
5. **Webcam Intruder Snapshot**: Automatically captures a snapshot via webcam upon detection of an unauthorized failed authentication attempt.
6. **Zero Password Storage**: Security-focused design that **never** captures, reads, or stores actual user passwords. Operates exclusively on official post-authentication Windows audit logs.
7. **Secure Credential Isolation**: Loads sensitive email credentials from environment variables (`EMAIL_USERNAME`, `EMAIL_APP_PASSWORD`, `ALERT_RECIPIENT_EMAIL`) with fallback to properties files or WinSW configuration.

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Camera.png" alt="Previews" width="25" height="25" /> Visual Previews & Screenshots

> 💡 *Click on any image preview below to open and view the full-resolution screenshot.*

<div align="center">

### 📧 Real-Time Email Alert Preview

[![Real-Time Email Security Alert](https://raw.githubusercontent.com/jeeva0405/Windows-Login-Intrusion-Detection-and-Real-Time-Security-Alert-System/main/assets/email-alert-preview.png)](https://raw.githubusercontent.com/jeeva0405/Windows-Login-Intrusion-Detection-and-Real-Time-Security-Alert-System/main/assets/email-alert-preview.png)

<br/>

### 📸 Webcam Intruder Evidence Panel

[![Webcam Intruder Capture Panel](https://raw.githubusercontent.com/jeeva0405/Windows-Login-Intrusion-Detection-and-Real-Time-Security-Alert-System/main/assets/intruder-capture-preview.png)](https://raw.githubusercontent.com/jeeva0405/Windows-Login-Intrusion-Detection-and-Real-Time-Security-Alert-System/main/assets/intruder-capture-preview.png)

</div>

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Triangular%20Ruler.png" alt="Architecture" width="25" height="25" /> System Architecture & Workflow


```
┌────────────────────────────────┐
│          Windows OS            │
│  (Lock Screen Authentication)  │
└───────────────┬────────────────┘
                │ User enters incorrect password
                ▼
┌────────────────────────────────┐
│   Windows Security Event Log   │
│         (Event ID 4625)        │
└───────────────┬────────────────┘
                │ Processed by wevtutil / PowerShell
                ▼
┌────────────────────────────────┐
│     WindowsLoginSentinel       │
│     (Java Background Loop)     │
└───────────────┬────────────────┘
                │ 1. Parse XML Event Details
                │ 2. Check record ID state (Prevent Duplicates)
                │ 3. Capture webcam photo evidence
                ▼
┌────────────────────────────────┐
│      Email Alert Service       │
│    (Jakarta Mail SMTP TLS)     │
└───────────────┬────────────────┘
                │ HTML Alert Sent
                ▼
┌────────────────────────────────┐
│          Device Owner          │
└────────────────────────────────┘
```

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Locked.png" alt="Locked" width="25" height="25" /> Security & Credentials Disclaimer

> [!IMPORTANT]
> **DO NOT HARDCODE REAL CREDENTIALS IN SOURCE CODE OR REPOSITORIES.**
> 
> Users **must manually replace placeholder values** in environment variables or configuration files with their own Gmail address and 16-character Gmail App Password. Real credentials should never be committed to Git, GitHub, or logged to disk. The application automatically masks all username and password values in output logs.

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Gear.png" alt="Gear" width="25" height="25" /> Environment Variables & Configuration

Set the following environment variables on your system, or configure them in `service/WindowsLoginSentinel.xml` / `config/config.properties`:

| Parameter / Variable | Description | Placeholder / Example |
| :--- | :--- | :--- |
| `EMAIL_USERNAME` | Sender email address | `YOUR_GMAIL_ADDRESS@gmail.com` |
| `EMAIL_APP_PASSWORD` | 16-character Gmail App Password | `YOUR_16_CHAR_APP_PASSWORD` |
| `ALERT_RECIPIENT_EMAIL` | Destination email for security alerts | `YOUR_ALERT_RECIPIENT@gmail.com` |

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Open%20File%20Folder.png" alt="Folder" width="25" height="25" /> Project Structure

```
WindowsLoginSentinel/
├── pom.xml                        # Maven build & dependencies configuration
├── config/
│   ├── config.properties          # Default SMTP & monitoring properties
│   └── state.properties           # Persistent record state (auto-generated)
├── service/
│   ├── WindowsLoginSentinel.xml   # WinSW service configuration (<env>, logs, startup)
│   ├── install-service.ps1       # Automated Administrator service installer script
│   └── uninstall-service.ps1     # Service removal script
├── assets/                        # Clickable project screenshots & diagrams
│   ├── architecture-diagram.png
│   ├── email-alert-preview.png
│   └── intruder-capture-preview.png
├── logs/                          # Windows Service output logs (auto-generated)
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── loginsentinel/
│   │               ├── Main.java                        # Entry point & CLI flags
│   │               ├── monitor/
│   │               │   └── WindowsLoginMonitor.java     # Event log polling
│   │               ├── event/
│   │               │   ├── LoginEvent.java              # Event data model
│   │               │   └── EventParser.java             # Windows XML parser
│   │               ├── email/
│   │               │   └── EmailAlertService.java       # HTML email alert dispatcher
│   │               ├── webcam/
│   │               │   └── WebcamCaptureService.java    # Webcam intruder snapshot
│   │               ├── security/
│   │               │   └── CredentialManager.java       # Environment & properties loader
│   │               └── service/
│   │                   └── WindowsServiceManager.java   # State persistence & WinSW scripts
│   └── test/
│       └── java/
│           └── com/
│               └── loginsentinel/                       # JUnit 5 & Mockito test suite
└── README.md
```

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Hammer%20and%20Wrench.png" alt="Build" width="25" height="25" /> Building & Running

### Prerequisites
- **JDK 17+** (JDK 17, 21, or 24 supported)
- **Apache Maven 3.8+**
- **Windows OS** (with Administrator access or membership in `Event Log Readers`)

### 1. Build Fat JAR
```powershell
mvn compile test package
```
This produces `target/WindowsLoginSentinel-1.0.0.jar`.

### 2. Send Test Email
Verify SMTP connection and credentials:
```powershell
java -jar target/WindowsLoginSentinel-1.0.0.jar --test-email
```

### 3. Check System Status & Diagnostics
```powershell
java -jar target/WindowsLoginSentinel-1.0.0.jar --status
```

### 4. Install and Run as a Background Windows Service (Recommended)
Open PowerShell as **Administrator**:
```powershell
powershell -ExecutionPolicy Bypass -File .\service\install-service.ps1
```

### 5. Verify Windows Service Status
```powershell
Get-Service -Name WindowsLoginSentinel
```

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Envelope.png" alt="Envelope" width="25" height="25" /> Sample Email Alert Text

**Subject**: `⚠️ Unauthorized Login Attempt Detected on LAPTOP-KD4GP10F`

```
⚠️ Windows Security Alert
Failed Authentication Event ID 4625

Computer Name:      LAPTOP-KD4GP10F
Username:           Jeeva
Domain / Workgroup: LAPTOP-KD4GP10F
Event Type:         Failed Windows Login (ID 4625)
Timestamp:          2026-07-26 01:30:45 PM IST
Logon Type:         Interactive (Keyboard / Lock Screen)
Failure Status:     Valid Username but Incorrect Password (0xc000006a)
IP / Source:        127.0.0.1

Please verify whether this login attempt was authorized.
```

---

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Shield.png" alt="Shield" width="25" height="25" /> Security Best Practices

- **Zero Password Interception**: Operates post-authentication by reading system audit logs generated by Windows Kernel.
- **Gmail App Passwords**: Use [Google App Passwords](https://myaccount.google.com/apppasswords) instead of account passwords.
- **Masked Logs**: Username and password strings are automatically masked in log outputs to prevent security leaks.
