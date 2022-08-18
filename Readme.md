# onPrivilege Module

## Synopsis
On-Privilege scanning module is a threat hunting tool for macOS Endpoint using EndpointSecurity Framework

## Motivation
One of the most dangous actions of malware is escape the privilege management of an infected host to execute more malicious behaviors. recent malware such as XCSSET.2020, MacMa.2021, dazzlespy.2022, CloudMensis.2022 all attempt to LPE on MacOS users. onPrivilege module continually monitors the system for events that may connect to privilege escalation attack. Specifically it watches for process rooting, bypass TCC, by SIP events.

To detect LPE on MacOS, this module does the following:
- Process rooting detection
- TCC.db file protection
- Legacy APP detection
- Special entitlement file tracking

**This is a prove-of-concept project, please always running in virtual machine.**
## Dependence
`brew install expect`

## build
```
mkdir ./build
cd ./build
cmake ..
make
```
## Usage
`sudo ./OPApplication`

## Todo
- [x] XPC service tracing
- [x] TCC.db manipulate
- [x] root privilege detect
- [ ] Protected folder collecting
- [ ] File attribute qurantine clear 

## Reference
### Related Tools
- macprocmon
  - https://github.com/gyunaev/macprocmon
- Shield
  - https://github.com/theevilbit/Shield
- ESFang
  - https://github.com/WithSecureLabs/ESFang
- ESFplayground
  - https://themittenmac.com/the-esf-playground/
- OverSight
  - https://github.com/objective-see/OverSight
- BlockBlock
  - https://github.com/objective-see/BlockBlock
