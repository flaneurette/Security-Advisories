# Quick mitigation

### Bug

Snooping tools (bpfcc-tools) installed by default on Ubuntu.

```
Bug Report: bpfcc-tools installed by default on Ubuntu Server 24.04
             via ubuntu-kernel-accessories

Package: ubuntu-kernel-accessories
Affects: Ubuntu Server 24.04 LTS (Noble)
Severity: Medium, perhaps High.
Type: Security / Default Install Policy
```

### Workaround:

```
apt remove bpfcc-tools bpftrace
apt-mark hold bpfcc-tools bpftrace
apt remove ubuntu-kernel-accessories
apt remove ubuntu-standard
apt autoremove
```

### Confirm:

```
dpkg -l | grep bpfcc
apt-mark showhold
```

### Extra check:

```
# Check current value (Best to have: 2, worst: 0.)
sysctl kernel.unprivileged_bpf_disabled

# Verify it's persistent
grep unprivileged_bpf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null

# If not found, add it
echo "kernel.unprivileged_bpf_disabled = 2" >> /etc/sysctl.conf
sysctl -p
```

If sysctl fails, set it to: 1

NOTE: The irony is that if it fails, often on a VPS, the admin has
no way to disable it permanently across reboots. This happens on
VPS hypervisors.

To prevent www-data PHP RCE, which could potentially invoke BPF
programs.

### Additional scans to perform

```
# World-writable files in web root:
find /var/www -perm -o+w 2>/dev/null -ls

# SUID files in web root:
find /var/www -perm /4000 2>/dev/null -ls

# Root-owned files in web directories:
find /var/www -user root 2>/dev/null -ls

If found, change ownership immediately:

# Example:
chown -R www-data:www-data /var/www
```

# Full Bug Report

```
Bug Report: bpfcc-tools installed by default on Ubuntu Server 24.04
             via ubuntu-kernel-accessories

Package: ubuntu-kernel-accessories
Affects: Ubuntu Server 24.04 LTS (Noble)
Severity: Medium, perhaps High.
Type: Security / Default Install Policy

Description:
-----------

When auditing my system, I came across "bpfcc-tools", without
recalling I ever installed it. (turns out I did not).

A default Ubuntu Server 24.04 installation silently installed
`bpfcc-tools` and `bpftrace` via the following dependency chain:

ubuntu-standard
    -> ubuntu-kernel-accessories (Recommends)
        -> bpfcc-tools
        -> bpftrace

Since apt honors Recommends by default, these packages are installed
on a default Ubuntu Server deployment without any explicit user
action or notification. This is worrisome.

Security Impact:
---------------

`bpfcc-tools` is not a passive debugging toolkit. It provides
kernel-level eBPF-based surveillance capabilities including:

- `bashreadline-bpfcc` - captures all bash input system-wide
  including passwords typed at prompts
- `sslsniff-bpfcc` - intercepts decrypted TLS traffic in memory
- `ttysnoop-bpfcc` - records all keystrokes in any TTY session
  including root sessions
- `opensnoop-bpfcc` - traces every file open call system-wide
- `execsnoop-bpfcc` - traces every process execution system-wide

If an attacker gains any foothold on the system, these tools are
immediately available without needing to install anything, transfer
any files, or trip any integrity checks. The tools are already
present, already trusted, and already have kernel-level access by
design.

"Living off the land" attacks:
-----------------------------

These tools make sniffing TLS connections, access bash shells,
sockets, prompts, and more, accessible by default (including to
insiders with access to the same server).

Tools that are frequently abused in post-exploitation:

- sslsniff-bpfcc is particularly concerning. This is an eBPF-based
  SSL/TLS sniffer that can intercept encrypted traffic in plaintext
  from within the host. It should almost never be on a production
  server.
- ttysnoop-bpfcc can attach to TTY sessions and record everything
  typed by other users, including root. This is a
  surveillance/credential-harvesting tool.
- sofdsnoop-bpfcc sniffs file descriptors passed over Unix sockets,
  which can expose sensitive IPC data.
- bashreadline-bpfcc and bashreadline.bt hook into readline and
  capture everything typed in bash shells system-wide, including
  passwords typed at prompts.
- opensnoop-bpfcc / opensnoop.bt trace every file open call
  system-wide, useful for discovering secret file paths.
- execsnoop.bt traces every process execution system-wide. Fine for
  debugging, dangerous if an attacker uses it to watch for
  privileged operations.

The entire bpfcc / bpftrace suite is a risk surface.

Insider Threat Concern:
----------------------

Because these tools are installed by default and have legitimate
surveillance-like behavior by design, any subtle malicious
modification to the package would be extremely difficult to detect.
The delta between legitimate and malicious behavior could be as
small as an additional network exfiltration call, which would blend
into the tool's normal operation profile.

Why this might be a valid concern:
----------------------------------

It slowly introduces things that are risky, then lets everyone warm
up to it, and then makes it default in Ubuntu. The XZ attacker's
playbook applied here:

The XZ backdoor author spent two years:

- Making legitimate contributions
- Building trust with maintainers
- Slowly gaining commit access
- Finally inserting the backdoor in a compressed binary blob that
  was hard to review

We never know what state-actors are up to, and whether they have
infiltrated and are warming people up to accept snooping tools in
Ubuntu by default. Perhaps I am wrong, but what if I am not?

Verification:
-------------

apt-cache policy bpfcc-tools
apt rdepends bpfcc-tools
apt depends ubuntu-kernel-accessories

Steps to reproduce:
-------------------

1. Install Ubuntu Server 24.04 LTS with default options
2. Run: dpkg -l | grep bpfcc
3. Observe bpfcc-tools installed without explicit user request

Expected behavior:
-----------------

bpfcc-tools and bpftrace should not be installed by default on
production servers. They should be available as explicit opt-in
packages for administrators who specifically need kernel-level
observability tooling.

Suggested fix:
--------------

Remove bpfcc-tools and bpftrace from the Recommends list in
`ubuntu-kernel-accessories`, or create a separate
ubuntu-kernel-debug-tools meta-package that administrators can
explicitly install when needed.

Workaround:
-----------

apt remove bpfcc-tools bpftrace
apt-mark hold bpfcc-tools bpftrace
apt remove ubuntu-kernel-accessories
apt remove ubuntu-standard
apt autoremove

Confirm:
-------

dpkg -l | grep bpfcc
apt-mark showhold

Also check:
----------

# Check current value (Best to have: 2, worst: 0.)
sysctl kernel.unprivileged_bpf_disabled

# Verify it's persistent
grep unprivileged_bpf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null

# If not found, add it
echo "kernel.unprivileged_bpf_disabled = 2" >> /etc/sysctl.conf
sysctl -p

If sysctl fails, set it to: 1

NOTE: The irony is that if it fails, often on a VPS, the admin has
no way to disable it permanently across reboots. This happens on
VPS hypervisors.

To prevent www-data PHP RCE, which could potentially invoke BPF
programs.

Additional scans to perform (to confirm PHP RCE cannot occur easily)
--------------------------------------------------------------------

# World-writable files in web root:
find /var/www -perm -o+w 2>/dev/null -ls

# SUID files in web root:
find /var/www -perm /4000 2>/dev/null -ls

# Root-owned files in web directories:
find /var/www -user root 2>/dev/null -ls

If found, change ownership immediately:

# Example:
chown -R www-data:www-data /var/www

--

Reporter: flaneurette
Tested on: Ubuntu 24.04 LTS Noble, kernel 6.8.0-101-generic

P.S. Things to consider:
------------------------

The cost-benefit analysis is completely lopsided:

1. Benefits of default inclusion:

- Convenient for the ~0.1% of programmers who do eBPF development
- Saves them one "apt install bpfcc-tools" command

Why? This seems a valid question to consider.

2. Costs of default inclusion:

- Kernel-level surveillance toolkit on every default Ubuntu server
- TLS bypass capability pre-positioned system-wide
- Complete LotL attack toolkit available to any attacker with
  foothold
- Millions of admins unaware it exists in production (banks,
  hospitals, governments)
- Impossible to detect if abused
- Pre-XZ threat model used to justify post-XZ risk

"Better user experience" and "convenience" are the most effective
social engineering vectors in technology policy precisely because
they are hard to argue against without sounding paranoid or
obstructionist. The pattern is well documented in intelligence
literature. It is called norm establishment or "Overton Window
manipulation." The goal is to shift what is considered acceptable
gradually:

- Start with "it's useful for debugging"
- Get it accepted as opt-in
- Move it to Recommends
- Eventually it becomes default
- Anyone questioning it is "anti-progress" or "making things
  harder for sysadmins"

Each step seems reasonable in isolation. The destination only
becomes visible when you zoom out.

"Better user experience" is particularly effective because:

- It is impossible to argue against without seeming difficult
- It appeals to the majority who prioritize convenience
- It reframes surveillance tools as helpful tools
- It shifts the burden of proof onto those raising concerns
- Removing it makes YOU look like the problem

The convenience argument for including it by default is extremely
weak on servers specifically.

Hope this helps.

/flaneurette
```