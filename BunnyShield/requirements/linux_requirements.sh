#!/bin/bash
 

sudo apt-get update && sudo apt-get upgrade -y

aptDepends=( 
               python3-pip 
               python3.10-venv
               auditd
               strace
           )


sudo apt-get install -y "${aptDepends[@]}" && sudo pip install -r python_requirements.txt