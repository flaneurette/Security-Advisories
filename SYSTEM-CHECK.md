# System Check.

A quick system check to run. Always useful to run these checks, for security hygiene. This document may be updated reguarly.


###  VPS Security

Checks you should run periodically, because a mistake is easy to make (even if you are experienced):

```
# World-writable files across server:
find /var/www -perm -o+w 2>/dev/null -ls

# SUID files across server:
find /var/www -perm /4000 2>/dev/null -ls

# Files not owned by root or www-data in web dirs
find /var/www ! -user root ! -user www-data 2>/dev/null

# Root owned files in web director(ies) across server:
find /var/www -user root 2>/dev/null -ls
```

If so, change it asap:

```
chown -R www-data:www-data /var/www
```

### Must-have packages

Have at least these installed for much more security:

```
sudo apt install -y unattended-upgrades needrestart debsums aide 
sudo apt install -y auditd lynis rkhunter fail2ban apparmor ssh-audit apt-listchanges libpam-tmpdir
```

Every once in a while review manually installed packages:

```
aptitude search '~i!~M' | grep -v "^i A"
```

### Risky packages

Clean the VPS from many `default packages` that are risky, to lessen attack landscape:

```
sudo apt remove eatmydata telnet inetutils-telnet swaks webalizer bpfcc-tools bpftrace strace trace-cmd apport 
sudo apt remove snapd modemmanager tnftp procmail rmail ruby-net-telnet arp-scan xclip sosreport 
sudo apt remove lxd-agent-loader lxd-installer multipath-tools
```

Then if Ubuntu:

```
apt remove ubuntu-kernel-accessories
```

The above prevent an upgrade to automatically install `bpfcc-tools`  again.

Then:

```
apt autoremove
```

### BPF

Be absolutely certain to remove it:

```
apt remove bpfcc-tools bpftrace
apt-mark hold bpfcc-tools bpftrace
apt remove ubuntu-kernel-accessories
apt remove ubuntu-standard
apt autoremove
```

Then:

```
# Check current value (Best to have: 2, worst: 0.)
sysctl kernel.unprivileged_bpf_disabled

# Verify it's persistent
grep unprivileged_bpf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null

# If not found, add it
echo "kernel.unprivileged_bpf_disabled = 2" >> /etc/sysctl.conf
sysctl -p
```

If sysctl -p fails, set it to: 1 instead of 2.

> NOTE: The irony is that if it fails, often on a VPS, the admin has no way to disable it permanently and survive reboots. Happens on VPS hypervisor.


### Disable core dumps

```
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -p
```

### Disable unused kernel protocols

```
cat >> /etc/modprobe.d/disable-unused-protocols.conf << 'EOF'
install dccp /bin/true
install rds /bin/true
install sctp /bin/true
install tipc /bin/true
EOF
```

### SSH & Issue

```
cat > /etc/issue << 'EOF'
Unauthorized access to this system is prohibited.
All activity is monitored and logged.
Disconnect immediately if you are not an authorized user.
EOF
```

Then:

```
cp /etc/issue /etc/issue.net
```

Then:

```
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 3
MaxSessions 2
ClientAliveCountMax 2
TCPKeepAlive no
LogLevel VERBOSE
EOF
```

Then:

```
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config.d/99-hardening.conf
sshd -t && systemctl restart ssh
```

### Motd

```
chmod -x /etc/update-motd.d/00-header
chmod -x /etc/update-motd.d/10-help-text
chmod -x /etc/update-motd.d/50-motd-news
chmod -x /etc/update-motd.d/50-landscape-sysinfo
```

Then run Lynis to get a fresh score:

```
sudo lynis audit system
```

Tools that are frequently abused in post-exploitation:

```
- sslsniff-bpfcc is particularly concerning. This is an eBPF-based SSL/TLS sniffer that can intercept encrypted traffic in plaintext from within the host. It should almost never be on a production server.
- ttysnoop-bpfcc can attach to TTY sessions and record everything typed by other users, including root. This is a surveillance/credential-harvesting tool.
- sofdsnoop-bpfcc sniffs file descriptors passed over Unix sockets, which can expose sensitive IPC data.
- bashreadline-bpfcc and bashreadline.bt hook into readline and capture everything typed in bash shells system-wide, including passwords typed at prompts.
- opensnoop-bpfcc / opensnoop.bt trace every file open call system-wide, useful for discovering secret file paths.
- execsnoop.bt traces every process execution system-wide. Fine for debugging, dangerous if an attacker uses it to watch for privileged operations.

The entire bpfcc / bpftrace suite is a risk surface

These are BPF/eBPF observability tools (from the BCC toolkit and bpftrace). Individually they are legitimate, but as a group they represent a powerful in-kernel monitoring and introspection framework. 
If an attacker gains any foothold, these tools give them deep visibility into the entire system with minimal noise. Consider whether all of them need to be present on a production machine.

Underrated risks that many sysadmins ignore you might want to consider:

- procmail is an old mail processing tool with a long history of vulnerabilities and privilege escalation bugs. It runs setuid on many systems. Unless you specifically need it for mail filtering, remove it.
- rmail is a legacy UUCP mail relay. Almost certainly not needed, and it has a history of exploitability.
- webalizer is an old web log analyzer with known vulnerabilities. If it is processing untrusted log data, it can be exploited.
- ModemManager has no obvious reason to be on a server. It increases attack surface unnecessarily.
- usb_modeswitch and usb_modeswitch_dispatcher deal with USB device switching. On a headless server or VPS this is almost certainly not needed and represents unnecessary attack surface.
- dhcpcd is a DHCP client daemon. On a server with static IPs, this should not be running. DHCP responses are unauthenticated and a rogue DHCP server on your network can push malicious routes or DNS servers.
- pollinate contacts an entropy server (Ubuntu's by default) to seed /dev/random at boot. This is a phone-home behavior that some consider a risk in high-security environments.
- vmhgfs-fuse and vmware-vmblock-fuse are VMware guest tools. If this is a VMware VM, these are expected, but they do represent a shared filesystem interface between host and guest that has had vulnerabilities historically.
```

# sshd_config

A quick ready to paste sshd_config.

```
nano /etc/ssh/sshd_config
```

Paste:

```
# SSH Server Configuration - Hardened
# !BE CAREFUL! it might lock you out. Read and edit carefully.

Port 22                      # Change if you want non-standard port
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

Protocol 2                   # Only SSH protocol 2

# Authentication
PermitRootLogin no            # ! Disable ROOT login !
PasswordAuthentication no     # Key-based auth only
ChallengeResponseAuthentication no
UsePAM yes                    # Needed for sudo and user auth
PubkeyAuthentication yes

# Key files
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Security / Encryption
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org

# Login settings
LoginGraceTime 30s
MaxAuthTries 3
MaxSessions 2
PermitEmptyPasswords no

# Access control
AllowUsers youruser          # Replace with your allowed SSH usernames
# AllowGroups sshusers       # Alternatively, use a group

# Connection options
ClientAliveInterval 60
ClientAliveCountMax 3
X11Forwarding no
PrintMotd no
TCPKeepAlive yes

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Misc
Banner /etc/issue.net           # Optional: legal warning message
```

# ssh_config

A quick ready to paste ssh_config.

```
nano /etc/ssh/ssh_config
```

Paste:

```
# SSH Client Configuration - Hardened

Include /etc/ssh/ssh_config.d/*.conf

Host *
    ForwardAgent no
    ForwardX11 no
    PasswordAuthentication no
    HostbasedAuthentication no
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no
    BatchMode no
    CheckHostIP yes
    AddressFamily any
    ConnectTimeout 10
    StrictHostKeyChecking ask
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile ~/.ssh/id_rsa
    Port 22
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-512,hmac-sha2-256
    EscapeChar ~
    SendEnv LANG LC_*
    HashKnownHosts yes
```

# Extra SSH Hardening conf.

We add this extra file, so that if the main ssh configs are somehow overwirtten, we still can load these extra security measures. Useful extra layer of defense.

```
nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Paste:

```
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 3
MaxSessions 2
ClientAliveCountMax 2
TCPKeepAlive no
LogLevel VERBOSE
```

# Sysctl config

A quick properly tested sysctl config if you need one.

```
nano /etc/sysctl.conf
```

Paste:

```
# WARNING: IPv6 is disabled. See 'Disable IPv6' section below.
# Run: `sysctl -p` after applying these settings.

# -------------------------------------------------------
# IPv6 - Disabled
# -------------------------------------------------------
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 0

# -------------------------------------------------------
# SYN Flood Protection
# -------------------------------------------------------
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# -------------------------------------------------------
# Connection Timeouts
# -------------------------------------------------------
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_rfc1337 = 1

# -------------------------------------------------------
# IP Spoofing and Source Routing
# -------------------------------------------------------
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# -------------------------------------------------------
# ICMP
# -------------------------------------------------------
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1

# -------------------------------------------------------
# Redirects
# -------------------------------------------------------
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# -------------------------------------------------------
# Logging
# -------------------------------------------------------
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# -------------------------------------------------------
# Network Performance
# -------------------------------------------------------
net.ipv4.ip_local_port_range = 1024 65535
net.core.bpf_jit_harden = 2

# -------------------------------------------------------
# Kernel Hardening
# -------------------------------------------------------
kernel.core_uses_pid = 1
kernel.sysrq = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
kernel.perf_event_paranoid = 3

# -------------------------------------------------------
# Filesystem
# -------------------------------------------------------
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.file-max = 65535

# -------------------------------------------------------
# Memory
# -------------------------------------------------------
vm.swappiness = 10

# -------------------------------------------------------
# TTY
# -------------------------------------------------------
dev.tty.ldisc_autoload = 0

# -------------------------------------------------------
# Connection Tracking (disabled - not using netfilter conntrack)
# -------------------------------------------------------
# net.netfilter.nf_conntrack_max = 1000000
# net.ipv4.netfilter.ip_conntrack_max = 1000000
```

---
