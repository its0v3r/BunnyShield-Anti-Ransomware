# BunnyShield

 Anti-ransomware software that uses a file system monitor, honeypots and the Linux audit service to detect and stop ransomware activity. Check the docs folder for more information.

[![Travis branch](https://img.shields.io/badge/made%20with-%3C3-red.svg)](https://github.com/its0v3r/BunnyShield)

# Features

- Stops most ransomwares for UNIX Systems in seconds
- Honeyfolder creation
- Smart and dynamic honeyfile updates
- Config to delete all honeyfiles in system
- High false-positive discernment
- Constat file system monitor
- Checks for different events to trigger a ransomware scan
- Slight to none performance impact
- Functionality to try finding and delete the malicious file
- Functionality to try finding and saving the ransomware key files
- Able to recover recently encrypted files with "AutoDecrypter" (works, but still WIP)

# How to use BunnyShield?

If you want to protect your system agaist Ransomware, simply run the BunnyShield compiled file in "BunnyShield-main/BunnyShield/bin/BunnyShield".
In the same folder, there is another file called "AutoDecrypter BETA" that will recover recently encrypted files by Ransomware. This is a WIP feature, and it should be executed after BunnyShield. 
