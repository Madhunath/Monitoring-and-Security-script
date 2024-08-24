#!/bin/bash

# Function to list all users and groups
list_users_and_groups() {
    echo "Listing all users and groups on the server:"
    cat /etc/passwd
    cat /etc/group
    echo
}

# Function to check for users with UID 0 (root privileges)
check_root_users() {
    echo "Checking for users with UID 0 (root privileges):"
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    echo
}

# Function to identify and report users without passwords or with weak passwords
check_weak_passwords() {
    echo "Identifying users without passwords or with weak passwords:"
    awk -F: '($2 == "" || length($2) <= 5) {print $1}' /etc/shadow
    echo
}

# Function to scan for files and directories with world-writable permissions
scan_world_writable() {
    echo "Scanning for world-writable files and directories:"
    find / -xdev -type f -perm -0002 -print
    find / -xdev -type d -perm -0002 -print
    echo
}

# Function to check .ssh directories and ensure they have secure permissions
check_ssh_permissions() {
    echo "Checking .ssh directories for secure permissions:"
    find /home -type d -name ".ssh" -exec chmod 700 {} \;
    find /home -type f -name "authorized_keys" -exec chmod 600 {} \;
    echo "Permissions fixed for .ssh directories and authorized_keys files."
    echo
}

# Function to report any files with SUID or SGID bits set
check_suid_sgid_files() {
    echo "Reporting files with SUID or SGID bits set:"
    find / -perm /6000 -type f -exec ls -l {} \;
    echo
}

# Function to list all running services and check for unauthorized services
check_running_services() {
    echo "Listing all running services:"
    systemctl list-units --type=service --state=running
    echo
}

# Function to check critical services (e.g., sshd, iptables) are running
check_critical_services() {
    echo "Checking if critical services are running:"
    for service in sshd iptables; do
        systemctl is-active --quiet $service && echo "$service is running." || echo "$service is NOT running!"
    done
    echo
}

# Function to check for non-standard or insecure ports
check_insecure_ports() {
    echo "Checking for non-standard or insecure ports:"
    netstat -tuln | grep -v ":22"  # Example: ignore port 22 (SSH)
    echo
}

# Function to verify firewall configuration
check_firewall() {
    echo "Verifying that a firewall is active and configured:"
    for firewall in iptables ufw; do
        if command -v $firewall > /dev/null 2>&1; then
            $firewall -L
        else
            echo "$firewall is not installed."
        fi
    done
    echo
}

# Function to check and report open ports
check_open_ports() {
    echo "Reporting open ports and associated services:"
    netstat -tulnp
    echo
}

# Function to check and report IP forwarding or insecure network configurations
check_ip_forwarding() {
    echo "Checking for IP forwarding and insecure network configurations:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding
    echo
}

# Function to identify public vs. private IP addresses
check_ip_addresses() {
    echo "Identifying public vs. private IP addresses:"
    ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
    ip -6 addr show | grep -oP '(?<=inet6\s)[\da-f:]+'
    echo
}

# Function to check for security updates and patches
check_security_updates() {
    echo "Checking for available security updates:"
    yum update | grep "^Inst" | grep -i security
    echo
}

# Function to monitor suspicious log entries
monitor_logs() {
    echo "Monitoring recent suspicious log entries:"
    grep "Failed password" /var/log/auth.log | tail -10
    echo
}

# Function to harden SSH configuration
harden_ssh() {
    echo "Hardening SSH configuration:"
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo "SSH password authentication disabled."
    echo
}

# Function to disable IPv6 if not required
disable_ipv6() {
    echo "Disabling IPv6:"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
    echo "IPv6 disabled."
    echo
}

# Function to secure the bootloader
secure_bootloader() {
    echo "Securing the bootloader:"
    echo "rootpw --iscrypted $(openssl passwd -1 password)" >> /etc/grub.conf
    echo "Bootloader password set."
    echo
}

# Function to configure automatic updates
configure_auto_updates() {
    echo "Configuring automatic updates:"
    yum install unattended-upgrades -y
    dpkg-reconfigure --priority=low unattended-upgrades
    echo
}

# Function to generate a summary report
generate_report() {
    echo "Generating security audit and hardening report..."
    # You can use the output of each function to create a detailed report
    echo "Security audit completed."
}

# Run all functions
list_users_and_groups
check_root_users
check_weak_passwords
scan_world_writable
check_ssh_permissions
check_suid_sgid_files
check_running_services
check_critical_services
check_insecure_ports
check_firewall
check_open_ports
check_ip_forwarding
check_ip_addresses
check_security_updates
monitor_logs
harden_ssh
disable_ipv6
secure_bootloader
configure_auto_updates
generate_report

echo "Security audit and hardening process completed!"

