# CyberArkTools
Some Python tooling to try to decrypt CyberArk .cred credential files

Research: https://research.nccgroup.com/2021/10/08/reverse-engineering-and-decrypting-cyberark-vault-credential-files/

## Verification Flag Breakdown
Vendor Documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/CreateCredFile-Utility.htm#CreateCredFileparameters
### Application Type (--appname)
This restriction limits what application types are able to use the .cred file. The options for this are: 
- CPM
- PVWA
- PVWAApp
- AppPrv
- PSMApp
- CABACKUP
- DR
- ENE
- WINCLIENT
- GUI
- PACLI
- XAPI
- NAPI
- EVD
- CACrypt

Source: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/11.3/en/Content/PASIMP/CreateCredFile-Utility.htm

### OS Username (--username)
The name of the user who can use this file. Typically specified in "domain\username" format. Example: SYSTEM -> "nt authority\system". This will normally also be a specific user created in the vault for initial setup purposes.

### Executable Path (--exepath)
Full path to the executable that is using the file.

### Machine IP (--machineip)
IP of the machine the .cred file is used on. In most cases this will be the local machine the file was found on, but CAN be a remote system.

### Machine Hostname (--hostname)
Hostname of the system the .cred file is used on. FQDN not required. In most cases this will be the local machine the file was found on, but CAN be a remote system.