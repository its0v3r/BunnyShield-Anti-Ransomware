# BunnyShield

 Anti-ransomware software that uses a file system monitor, honeypots and the Linux audit service to detect and stop ransomware activity. Check the docs folder for more information.

[![Travis branch](https://img.shields.io/cran/l/devtools.svg)](https://github.com/its0v3r/BunnyShield/blob/main/LICENSE)
[![Travis branch](https://img.shields.io/badge/made%20with-%3C3-red.svg)](https://github.com/its0v3r/BunnyShield)

# Features

- Stops most ransomwares for UNIX Systems in seconds
- Smart and dynamic honeyfile updates
- High false-positive discernment
- Constat file system monitor
- Checks for different events to trigger a ransomware scan
- Able to recover recently encrypted files with "AutoDecrypter" (works, but still WIP)

# How to use BunnyShield?

If you want to protect your system agaist Ransomware, simply run the BunnyShield compiled file in "BunnyShield-main/BunnyShield/bin/BunnyShield".
In the same folder, there is another file called "AutoDecrypter BETA" that will recover recently encrypted files by Ransomware. This is a WIP feature, and it should be executed after BunnyShield. 
