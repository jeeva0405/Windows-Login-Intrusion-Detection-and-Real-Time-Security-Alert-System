# 🛡️ Windows Login Sentinel

**Real-Time Failed Login Detection & Email Alert System**

Windows Login Sentinel is a Java-based background security service designed to protect Windows computers from unauthorized access attempts. It continuously monitors the Windows Security Event Log for failed authentication attempts (**Event ID 4625**), extracts crucial metadata (username, workstation, timestamp, logon type, failure reason, IP address), prevents duplicate alert notifications via state tracking, and immediately dispatches email alerts to the system owner.

---

## 📌 Features

1. **Automatic Background Execution**: Runs as a silent background Windows Service on system startup using WinSW (Windows Service Wrapper).
2. **Real-Time Failed Login Detection**: Instantly identifies Event ID 4625 when an incorrect password is entered at the lock screen, RDP session, or network login.
3. **Duplicate Event Prevention**: Maintains persistent state (`config/state.properties`) recording the last processed `EventRecordID` to ensure each failed attempt triggers **exactly one** email alert.
4. **Rich HTML & Text Email Alerts**: Dispatches security emails containing formatted incident tables, logon type explanations, failure reason descriptions, and device details via Jakarta Mail & SMTP (supporting Gmail App Passwords, Outlook, etc.).
5. **Zero Password Storage**: Security-focused design that **never** captures, reads, or stores actual user passwords. Operates exclusively on official post-authentication Windows audit logs.
6. **Secure Credential Isolation**: Loads sensitive email credentials from environment variables (`EMAIL_USERNAME`, `EMAIL_APP_PASSWORD`, `ALERT_RECIPIENT_EMAIL`) with fallback to properties files or WinSW service environment tags (`<env name="..." value="..."/>`).

---

## 🔒 Security & Credentials Disclaimer

> [!IMPORTANT]
> **DO NOT HARDCODE REAL CREDENTIALS IN SOURCE CODE OR REPOSITORIES.**
> 
> Users **must manually replace placeholder values** in environment variables or configuration files with their own Gmail address and 16-character Gmail App Password.
> Real credentials should never be committed to Git, GitHub, or logged to disk. The application automatically masks all username and password values in output logs.

---

## ⚙️ Environment Variables & Configuration

Set the following environment variables on your system, or configure them in `service/WindowsLoginSentinel.xml` / `config/config.properties`:

| Parameter / Variable | Description | Placeholder / Example |
| :--- | :--- | :--- |
| `EMAIL_USERNAME` | Sender email address | `YOUR_GMAIL_ADDRESS@gmail.com` |
| `EMAIL_APP_PASSWORD` | 16-character Gmail App Password | `YOUR_16_CHAR_APP_PASSWORD` |
| `ALERT_RECIPIENT_EMAIL` | Destination email for security alerts | `YOUR_ALERT_RECIPIENT@gmail.com` |

---

## 🏗️ Architecture & Workflow

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
                │ 3. Extract metadata
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

## 📁 Project Structure

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

## 🚀 Building & Running

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

## ✉️ Sample Email Alert

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

## 🛡️ Security Best Practices

- **Zero Password Interception**: Operates post-authentication by reading system audit logs generated by Windows Kernel.
- **Gmail App Passwords**: Use [Google App Passwords](https://myaccount.google.com/apppasswords) instead of account passwords.
- **Masked Logs**: Username and password strings are automatically masked in log outputs to prevent security leaks.
