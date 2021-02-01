<p align="center"><img src="logo.png" alt="SSH Controls Logo"></p>

## What's new

:loudspeaker: **30/12/2020**:
* added support for standard home directory location for public keys (`$HOME/.ssh`). Set `key_location=use_sshd` in `update_ssh.conf[.local]` with `AuthorizedKeysFile` set to the default value in `sshd_config` (or use the value `.ssh/authorized_keys`). *Caveat*: SSH Controls will not create parent nor intermediate directories in the public key file path if they are missing.
* added support for SELinux (CentOS/RHEL 8.x)
* various fixes

## About

SSH Controls is a light-weight SSH **public key** distribution & management framework

* uses a **desired state** model: SSH Controls *pushes* public keys from a key master (or slave) server onto client host(s) and applies them according to the central configuration.

* uses **SSH** as **transport** mechanism: eat your own dog food. SSH Controls connects to client hosts through the secure path of SSH and using a public key that is under its own control.

* supports a **Master→Slave→Client** model so that information can be propagated within more complex LAN set-ups.

* can **shield** public keys from owners/users on client systems: SSH Controls may require the standard `sshd_config` to be reconfigured with an alternate path for the `AuthorizedKeysFile` setting so that public keys are stored in common location which cannot be manipulated by the owners of the public keys. This allows for more administrative control and better security.

* performs operations with **least privileges**: copy/distribute operations are performed with a low-privileged account. Only the actual key updates requires super-user privileges which need to be configured via SUDO.

* uses a **two-stage** approach to **activate** public keys: copy (or distribute) and apply. Keys are first copied into a temporary location on each client hosts - the holding directory - and not applied automatically. Applying or activating keys on a client host is a separate operation which can be triggered either locally or remotely (from the SSH master)

* can assign a single public key to **multiple** OS accounts: SSH Controls allows an user to log on under multiple accounts using the same key. Auditing of the connecting user and the target account is possible using fingerprinting.

* allows the use of (nested) **groups** in the master configuration: users, keys and hosts can be grouped in the SSH master configuration files to allow a simplified configuration. Nesting of groups is allowed up to *5 levels* deep.

* allows the use of (nested) **groups** in the specification of the *push* targets. Either via the `--targets` command-line parameter or via the `targets` configuration file.

* allows compromised public keys to be **blacklisted**: SSH Controls will deny the use of public keys that have been administrative blacklisted. Blacklisting happens on the SSH master and is applied to all client hosts.

* can discover host public keys to (re)create `known_hosts` file(s) for a large amount of hosts

* supports *md5* and *sha512* fingerprint **hashes** (if the installed SSH version supports these hash types)

* requires **no client agent** component and is **stateless**: SSH Controls performs operations by pushing keys or commands to client hosts. Update processes on the client hosts will only be started on-demand. If the SSH master is - for whatever reason - unavailable then active keys on a client host remain in place and logons are still possible.

* is **easy** to **configure** and **maintain** (command-line based): the configuration is stored in a limited number of flat files and be easily updated. A very rudimentary syntax checking facility is also available to check the consistency of the most important (master) configuration files.


SSH Controls does NOT:

* manage or distribute SSH **private keys**: SSH private keys should be controlled and managed (and safeguarded!) by the actual owners. Though one could consider SSH key pairs of generic accounts (such as application accounts) as an exception, SSH Controls currently does not support the management of private keys.

More documentation can be found at <http://www.kudos.be/ssh_controls/>

*Logo created with [Free Logo Maker](https://logomakr.com)*
