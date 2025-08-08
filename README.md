# SecureTheWorld
This is my repo of CyberPatriot scripts on my journey to SecureTheWorld

# CyberPatriot Windows Hardening Script

**Author:** *William Torres*  
**Version:** 1.0  
**Compatibility:** Windows 10 / Windows 11 (Admin Privileges Required)

---

## Overview

`secure_windows.ps1` is a **prompt-driven Windows hardening script** designed specifically for **CyberPatriot competitions** and similar security challenges.  

This script:
- Strengthens **user accounts**, **Group Policy Objects**, **Local Security Policies**, and **Windows firewall rules**
- Scans and prompts removal of suspicious **apps, services, and hacking tools**
- Enforces strong **password and lockout policies**
- Enables **comprehensive auditing** for both success and failure events
- Implements **Windows Firewall best practices**
- Logs everything with timestamps and generates a **summary report**  

**Golden Rule:** *The script **always prompts** before making any change that could potentially break the image.*

---


## 📂 File Setup

When using this script:
- Place `secure_windows.ps1` in **any directory** on your competition image  
- Create a `Users.txt` file in **the same directory** as `secure_windows.ps1` before running  
- This repo only contains the script and documentation — **Users.txt will be unique to your image**

---

## 📜 Users.txt Format

The `Users.txt` file controls who is authorized on the machine and who should have admin rights.

**Example:**
adminuser; admin
regularuser;
techuser; admin
guestuser;

**Rules:**
- One user per line
- `; admin` means the user should be in the **Administrators** group
- No entry = not authorized (you will be prompted to remove them)

---

## 🚀 Usage

1. **Clone this repo directly to the target image**
   ```powershell
   git clone https://github.com/bluebirdOT/SecureTheWorld.git
   cd SecureTheWorld
2. Copy the script to your working directory
   ```powershell
   Copy-Item .\secure_windows.ps1 C:\'working_directory'\
3. Create Users.txt in same directory as secure_windows.ps1
   ```powershell
   notepad C:\\'working_directory'\Users.txt
fill it with authorized accounts
4. Run PowerShell as Administrator
5. Allow temporary script execution

6. Run the script where both files are located
