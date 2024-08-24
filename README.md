# Security Audit and Hardening Script

## Overview

This script performs a comprehensive security audit and hardening of a Linux server. It includes checks for user and group configurations, file permissions, running services, network configurations, firewall settings, and more. The goal is to identify potential security vulnerabilities and implement best practices to enhance the security of the server.

## Prerequisites

- A Linux-based system (e.g., CentOS, Ubuntu)
- Root or sudo privileges
- Basic knowledge of Linux command-line operations

## Script Functions

1. **List Users and Groups**: Displays all users and groups on the server.
2. **Check Root Users**: Identifies users with UID 0 (root privileges).
3. **Check Weak Passwords**: Identifies users without passwords or with weak passwords.
4. **Scan World-Writable Files**: Finds files and directories with world-writable permissions.
5. **Check SSH Permissions**: Ensures that `.ssh` directories and `authorized_keys` files have secure permissions.
6. **Check SUID/SGID Files**: Reports files with SUID or SGID bits set.
7. **Check Running Services**: Lists all running services and checks for unauthorized services.
8. **Check Critical Services**: Ensures critical services like SSH and iptables are running.
9. **Check Insecure Ports**: Reports non-standard or insecure open ports.
10. **Check Firewall**: Verifies that a firewall is active and properly configured.
11. **Check Open Ports**: Lists open ports and associated services.
12. **Check IP Forwarding**: Checks for IP forwarding and insecure network configurations.
13. **Check IP Addresses**: Identifies public and private IP addresses.
14. **Check Security Updates**: Checks for available security updates and patches.
15. **Monitor Logs**: Monitors recent suspicious log entries for failed login attempts.
16. **Harden SSH Configuration**: Disables SSH password authentication for enhanced security.
17. **Disable IPv6**: Disables IPv6 if it is not required.
18. **Secure Bootloader**: Sets a password for the bootloader.
19. **Configure Automatic Updates**: Installs and configures automatic updates.
20. **Generate Report**: Provides a summary of the audit and hardening process.

## Usage

1. **Download the Script**: Save the script to a file, e.g., `security_audit.sh`.
2. **Make the Script Executable**:

   chmod +x security_audit.sh

## Run The Script 

   sudo ./security_audit.sh
