# Modules imports
import time
import re
import os
import subprocess

# Files imports
from utils.logger import logger
from app.config_handler import RegexConfig as regexconf
from app.config_handler import AuditConfig as auditconf
from app.config_handler import HoneyConfig as honeyconf


class Audit:
    def setStatus(action):
        """Function to turn Audit service on or off"""
        output = subprocess.run(['service', 'auditd', 'status'],
                                capture_output=True, text=True)
        tries = 0
        if not "could not be found" in str(output):
            # Turn Audit service on
            if action == "on":
                while True and tries < 5:
                    if re.findall(regexconf.ACTIVE_REG_PATTERN, str(output))[0] == "active":
                        logger.debug("Auditd Service is currently active.")
                        break
                    else:
                        logger.debug("Auditd Service is currently inactive.")
                        logger.debug("Turning Auditd service on.")
                        subprocess.run(['service', 'auditd', 'start'])
                        time.sleep(3)
                        output = subprocess.run(['service', 'auditd', 'status'],
                                                capture_output=True, text=True)
                        tries += 1

            # Turn Audit service off
            elif action == "off":
                if re.findall(regexconf.ACTIVE_REG_PATTERN, str(output))[0] == "inactive":
                    logger.error("Can't turn Auditd Service off. The service is already inactive.")
                else:
                    logger.debug("Turning Auditd service off.")
                    subprocess.run(['service', 'auditd', 'stop'], capture_output=False, text=False, stderr=subprocess.DEVNULL)
        else:
            logger.debug("Could not find Auditd service. Do you have Auditd installed?")

    #

    def createCustomRuleFile():
        """Funtion to create the BunnyShield audit rules file"""
        subprocess.check_output([f"auditctl -D -k {auditconf.FILE_EVENT_RULE_NAME}"], shell=True, stderr=subprocess.DEVNULL)
        subprocess.check_output([f"auditctl -D -k {auditconf.FILE_OPEN_SHELL_RULE_NAME}"], shell=True, stderr=subprocess.DEVNULL)

        if os.path.exists(auditconf.PATH_TO_AUDIT_CUSTOM_RULES_FILE):
            os.remove(auditconf.PATH_TO_AUDIT_CUSTOM_RULES_FILE)

        with open(auditconf.PATH_TO_AUDIT_CUSTOM_RULES_FILE, "w") as f:
            f.write("")

    #

    def createAuditRule(path_to_dir):
        """Funtion to create a BunnyShield audit rule for a directory"""
        with open(auditconf.PATH_TO_AUDIT_CUSTOM_RULES_FILE, "a") as f:
            f.write(f'-w "{path_to_dir}" -p wa -k bs-file-event\n')

    #

    def deleteCustomRuleFile():
        """Function to delete the BunnyShield audit rules file"""
        logger.debug(f"Deleting the custom rules file.")
        if os.path.exists(auditconf.PATH_TO_AUDIT_CUSTOM_RULES_FILE):
            os.remove(auditconf.PATH_TO_AUDIT_CUSTOM_RULES_FILE)
        else:
            logger.error("No custom rule file was found.")

    #

    def deleteRules():
        """Funtion to delete all BunnyShield audit rules"""
        logger.debug("Deleting audit rules foreach selected directory.")
        rule_count = subprocess.check_output([f"sudo auditctl -l -k {auditconf.FILE_EVENT_RULE_NAME} | wc -l"], shell=True, stderr=subprocess.DEVNULL).decode()
        initial_rule_count = rule_count

        start = time.perf_counter()
        subprocess.check_output([f"auditctl -D -k {auditconf.FILE_EVENT_RULE_NAME}"], shell=True, stderr=subprocess.DEVNULL)
        subprocess.check_output([f"auditctl -D -k {auditconf.FILE_OPEN_SHELL_RULE_NAME}"], shell=True, stderr=subprocess.DEVNULL)

        while int(rule_count) > 1:
            rule_count = subprocess.check_output([f"sudo auditctl -l -k {auditconf.FILE_EVENT_RULE_NAME} | wc -l"], shell=True, stderr=subprocess.DEVNULL).decode()
            time.sleep(1)

        end = time.perf_counter()
        logger.debug(f"Deleted a total of {str(initial_rule_count).strip()} audit rules in {round(end - start, 3)}s.")

    #

    def loadRules():
        """Funtion to load all BunnyShield audit rules"""
        start = time.perf_counter()
        logger.debug("Creating audit rules foreach selected directory.")
        logger.debug(f"It will be created {len(honeyconf.DIRECTORIES)} audit rules.")

        with open(auditconf.PATH_TO_AUDIT_CUSTOM_RULES_FILE) as f:
            # Load file event rules foreach directory
            for rule in f:
                subprocess.check_output([f"auditctl {rule.strip()}"], shell=True, stderr=subprocess.DEVNULL)

            # Load open shell event rule
            subprocess.check_output([f"auditctl -a exit,always -F arch=b64 -S execve -F path=/bin/sh -k bs-open-shell-event"],  shell=True, stderr=subprocess.DEVNULL)

            # Check if all rules have been loaded
            rule_count = 0
            while int(rule_count) < int(len(honeyconf.DIRECTORIES)):
                rule_count = subprocess.check_output([f"auditctl -l -k bs-file-event | wc -l"], shell=True, stderr=subprocess.DEVNULL).decode()
                time.sleep(1)

        end = time.perf_counter()
        logger.debug(f"Loaded a total of {int(rule_count)} audit rules in {round(end - start, 3)}s.")
