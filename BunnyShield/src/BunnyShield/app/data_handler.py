# Module imports
import hashlib
import os
import json
import pathlib
import re
import subprocess
import time
from app.audit_handler import Audit

# File imports
from utils.logger import logger
from utils.helper import randomString
from app.config_handler import GeneralConfig as generalconf
from app.config_handler import AuditConfig as auditconf
from app.config_handler import HoneyConfig as honeyconf
from app.config_handler import FileMonitorConfig as monitorconf
from app.config_handler import RegexConfig as regexconf


class DataCreator:
    def checkAndCreateConfigFolder():
        """Function to check if the config folder exists and create one"""
        if not os.path.exists(generalconf.PATH_TO_BUNNYSHIELD_CONFIG):
            os.makedirs(generalconf.PATH_TO_BUNNYSHIELD_CONFIG)

    #

    def checkAndCreateDataFolder():
        """Function to check if the config folder exists and create one"""
        if not os.path.exists(generalconf.PATH_TO_BUNNYSHIELD_DATA):
            os.makedirs(generalconf.PATH_TO_BUNNYSHIELD_DATA)

    #

    def createHoneyfilesJson(honeypot_files_hash_list):
        """Function to create a JSON file with all honeyfiles absolute paths and it's respective hashes"""
        logger.debug("Creating honeyfiles JSON.")
        json_object = json.dumps(honeypot_files_hash_list, indent=4)

        with open(generalconf.PATH_TO_JSON_FILE, 'w') as f:
            f.write(json_object)

    #

    def createHoneyfilesNamesTxt(honeypot_names_list):
        """Function to create a TXT file with all honeyfile unique names"""
        logger.debug("Creating honeyfiles names TXT.")

        with open(generalconf.PATH_TO_TXT_FILE, 'w') as f:
            for name in honeypot_names_list:
                f.write(f"{name}\n")

    #

    def createConfigFile():
        """Function to create a JSON file with all BunnyShield configuration"""

        config_dict = {
            "general-config": {
                "honeyfile-json-alias": generalconf.HONEYFILE_JSON_ALIAS,
                "honeyfile-txt-alias": generalconf.HONEYFILE_NAMES_TXT_ALIAS
            },
            "audit-config": {
                "file-event-rule-name": auditconf.FILE_EVENT_RULE_NAME,
                "file-event-open-shell-name": auditconf.FILE_OPEN_SHELL_RULE_NAME,
            },
            "honey-config": {
                "action": honeyconf.HONEY_ACTION,
                "path-to-honeyfolder": honeyconf.PATH_TO_HONEYFOLDER,
                "path-to-whitelistedfolder": honeyconf.PATH_TO_WHITELISTED_FOLDER,
                "directories": honeyconf.DIRECTORIES,
                "honeyfile-prefix": honeyconf.HONEYFILE_PREFIX

            },
            "file-monitor-config": {
                "skip-to-monitor": True,
            }}

        json_object = json.dumps(config_dict, indent=4)

        with open(os.path.join(generalconf.PATH_TO_BUNNYSHIELD_CONFIG, "bs-config.json"), 'w') as f:
            f.write(json_object)

    #

    def createSingleHoneyfile(event_path):
        try:
            honeypot_dict = ""

            if os.access(event_path, os.W_OK):
                honeyfile_name = honeyconf.HONEYFILE_PREFIX + randomString("unique-name") + '.txt'
                honeyfile_absolute_path = os.path.join(event_path, honeyfile_name)

                with open(honeyfile_absolute_path, 'w') as f:
                    f.write("THIS IS A BUNNYSHIELD FILE! PLEASE, DO NOT MOVE, DELETE, RENAME OR MODIFY THIS FILE! YOU ARE STILL FREE TO MOVE ANY FOLDER THAT CONTAINS A FILE LIKE THIS.\n")
                    f.write(f"Credit card details: {randomString('unique-number')}")

                with open(honeyfile_absolute_path, 'rb') as f:
                    honeypot_dict = DataCreator.createHoneyfileDataDict(f)

                subprocess.check_output([f'chmod 666 "{honeyfile_absolute_path}"'], shell=True, stderr=subprocess.DEVNULL)
                subprocess.check_output([f'chown {generalconf.USER} "{honeyfile_absolute_path}"'], shell=True, stderr=subprocess.DEVNULL)

            return honeypot_dict, honeyfile_name

        except Exception as e:
            logger.error(e)

    #

    def createHoneyfileDataDict(honeypot_file):
        """Function to return a honeyfile dict with an absolute path and a hash"""
        file_data = honeypot_file.read()
        readable_hash = hashlib.sha1(file_data).hexdigest()

        honeypot_file_hash_dict = {
            "absolute_path": honeypot_file.name,
            "hash": readable_hash
        }
        return honeypot_file_hash_dict

    #


class DataUpdater:
    def checkForHoneyFilesJsonIntegrity():
        """Function to check the integrity of honeyfiles, unnecessary honyefiles etc"""
        Audit.createCustomRuleFile()
        json_data = DataUpdater.getHoneyfileJsonData()

        missing_honeyfiles = []
        honeyfiles_not_part_of_any_monitored_dir = []

        # Check for missing directories
        current_directory_list = []
        for directory in honeyconf.DIRECTORIES:
            if os.path.exists(directory):
                current_directory_list.append(directory)

        honeyconf.DIRECTORIES = current_directory_list

        # If no directories were found
        if not honeyconf.DIRECTORIES:
            honeyconf.DIRECTORIES = [
                generalconf.PATH_TO_HOME_FOLDER, generalconf.PATH_TO_ETC_FOLDER
            ]
        if json_data:
            # Check for missing honeyfiles
            for dict in json_data:
                remove = False
                has_dir = False

                if not os.path.exists(dict['absolute_path']):
                    missing_honeyfiles.append(dict['absolute_path'])

                for directory in honeyconf.DIRECTORIES:
                    if directory not in dict['absolute_path'] and not has_dir:
                        remove = True
                        has_dir = True
                    else:
                        remove = False
                        break

                if remove:
                    honeyfiles_not_part_of_any_monitored_dir.append(dict['absolute_path'])

            # Delete honeyfiles entries in JSON that aren present in the JSON, and aren a part of any monitored directories
            if missing_honeyfiles:
                logger.debug(f"There are {len(missing_honeyfiles)} honeyfiles missing. The JSON data will be updated.")
                DataUpdater.updateDelete(missing_honeyfiles, json_data)
                json_data = DataUpdater.getHoneyfileJsonData()

            # Delete honeyfiles entries in JSON that are present in the JSON, but aren't a part of any monitored directories
            if honeyfiles_not_part_of_any_monitored_dir:
                logger.debug(f"There are {len(honeyfiles_not_part_of_any_monitored_dir)} unecessary honeyfiles in the JSON file. Deleting the unecessary honeyfiles entries.")
                DataUpdater.updateDelete(honeyfiles_not_part_of_any_monitored_dir, json_data)
                json_data = DataUpdater.getHoneyfileJsonData()

            # Check for honeyfiles that exists, but are not present in the JSON or the hash is invalid
            honeyfiles_to_delete = []
            folder_to_create_honeyfiles = []
            honeyfiles_dict_list = []

            for directory in honeyconf.DIRECTORIES:
                Audit.createAuditRule(directory)
                for current_path, folders_in_current_path, files_in_current_path in os.walk(directory):
                    try:
                        if not generalconf.PATH_TO_BUNNYSHIELD in current_path or not honeyconf.PATH_TO_WHITELISTED_FOLDER in current_path:
                            if os.access(current_path, os.W_OK):
                                honeyfiles_with_entry_in_folder = 0

                                for file in files_in_current_path:
                                    if honeyconf.HONEYFILE_PREFIX in file:
                                        has_json_entry = False
                                        file_absolute_path = os.path.join(current_path, file)

                                        for dict in json_data:
                                            if file_absolute_path in dict['absolute_path']:
                                                with open(file_absolute_path, 'rb') as f:
                                                    file_data = f.read()
                                                    current_hash = hashlib.sha1(file_data).hexdigest()
                                                    if current_hash == dict['hash']:
                                                        has_json_entry = True
                                                        honeyfiles_with_entry_in_folder += 1
                                                        break

                                        if not has_json_entry:
                                            honeyfiles_to_delete.append(file_absolute_path)

                                if honeyfiles_with_entry_in_folder == 0:
                                    if len(folders_in_current_path) == 0:
                                        folder_to_create_honeyfiles.append(current_path)

                                    elif str(pathlib.Path(re.findall(regexconf.PATH_WITHOUT_FILE_PATTERN, current_path)[0])) == directory:
                                        folder_to_create_honeyfiles.append(current_path)

                                    elif current_path == directory:
                                        folder_to_create_honeyfiles.append(current_path)

                    except Exception as e:
                        logger.error(e)
                        continue

            # Delete honeyfiles without an entry in the JSON
            if honeyfiles_to_delete:
                logger.debug(f"There are {len(honeyfiles_to_delete)} unecessary honeyfiles in the monitored directories. Deleting the unecessary honeyfiles.")
                for honeyfile_path in honeyfiles_to_delete:
                    os.remove(honeyfile_path)

            # Create honeyfiles for folders without honeyfiles, but should have honeyfiles
            if folder_to_create_honeyfiles:
                logger.debug(f"There are {len(folder_to_create_honeyfiles)} folders that should have honeyfiles without it. Creating the honeyfiles.")
                for folder in folder_to_create_honeyfiles:
                    new_honeyfile_dict, _ = DataCreator.createSingleHoneyfile(folder)
                    honeyfiles_dict_list.append(new_honeyfile_dict)

                DataUpdater.updateCreate(honeyfiles_dict_list, [], json_data)
                json_data = DataUpdater.getHoneyfileJsonData()

            Audit.loadRules()
            return True

        else:
            return False

        #

    def getHoneyfileJsonData():
        """Function to get the honeyfiles JSON data"""
        try:
            with open(generalconf.PATH_TO_JSON_FILE) as f:
                json_file_data = json.load(f)
            return json_file_data

        except FileNotFoundError:
            logger.error(f'Could not find {generalconf.HONEYFILE_JSON_ALIAS} in {generalconf.PATH_TO_BUNNYSHIELD_CONFIG}')

    #

    def getHoneyfileTxtData():
        """Function to get the honeyfiles names TXT data"""
        try:
            honeypot_names_data = []
            with open(os.path.join(generalconf.PATH_TO_TXT_FILE), "r") as f:
                for line in f:
                    honeypot_names_data.append(line.rstrip())
                return honeypot_names_data

        except:
            logger.error(f'Could not find {generalconf.HONEYFILE_NAMES_TXT_ALIAS} in {generalconf.PATH_TO_BUNNYSHIELD_CONFIG}')

    #

    def updateCreate(honeypot_dicts, honeypot_old_and_new_dicts, json_data):
        """Function to update the honeyfile JSON for create events"""
        start = time.perf_counter()

        try:
            for honeypot_dict in honeypot_dicts:
                json_data.append(honeypot_dict)

            if honeypot_old_and_new_dicts:
                for element in json_data:
                    already_appended = False
                    for honeypot_dict in honeypot_old_and_new_dicts:
                        if not already_appended:
                            if honeypot_dict['old_path'] in element['absolute_path']:
                                element['absolute_path'] = honeypot_dict['new_path']
                                already_appended = True

            with open(generalconf.PATH_TO_JSON_FILE, "w") as f:
                json.dump(json_data, f)

            for honeypot_dict in honeypot_dicts:
                honeypot_file_name = pathlib.Path(re.findall(regexconf.FILE_IN_PATH_PATTERN, honeypot_dict['absolute_path'])[0])
                DataUpdater.updateHoneypotNamesTxt([honeypot_file_name], 'create')

            end = time.perf_counter()
            logger.debug(f"Updated JSON for CREATE event in {round(end - start, 3)}s.")

        except Exception as e:
            logger.error(e)

    #

    def updateMoveOrRename(honeypot_old_and_new_dicts, json_file_data):
        """Function to update the honeyfile JSON for move or rename events"""
        start = time.perf_counter()
        new_json_file_data = []
        try:
            for element in json_file_data:
                for honeypot_dict in honeypot_old_and_new_dicts:
                    if honeypot_dict['old_path'] in element['absolute_path']:
                        element['absolute_path'] = honeypot_dict['new_path']
                new_json_file_data.append(element)

            with open(generalconf.PATH_TO_JSON_FILE, 'w') as f:
                f.write(json.dumps(new_json_file_data, indent=4))

            end = time.perf_counter()
            logger.debug(f"Updated JSON for UPDATE event in {round(end - start, 3)}s.")

        except Exception as e:
            logger.error(e)

    #

    def updateDelete(event_paths, json_data):
        """Function to update the honeyfile JSON for delete events"""
        start = time.perf_counter()

        try:
            new_json_data = []
            names_to_delete = []

            for element in json_data:
                for event_path in event_paths:
                    if event_path in element['absolute_path']:
                        if event_path not in names_to_delete:
                            names_to_delete.append(element['absolute_path'])

            for element in json_data:
                if element['absolute_path'] in names_to_delete:
                    pass
                else:
                    new_json_data.append(element)

            with open(generalconf.PATH_TO_JSON_FILE, 'w') as f:
                f.write(json.dumps(new_json_data, indent=4))

            end = time.perf_counter()
            logger.debug(f"Updated JSON for DELETE event in {round(end - start, 3)}s.")

            DataUpdater.updateHoneypotNamesTxt(names_to_delete, "delete")

        except Exception as e:
            logger.error(e)

    #

    def updateHoneypotNamesTxt(honeypot_names, action):
        """Function to update the honeyfile TXT"""
        if action == "create":
            try:
                with open(generalconf.PATH_TO_TXT_FILE, 'a') as f:
                    for honeypot_name in honeypot_names:
                        f.write(f"{honeypot_name}\n")
            except Exception as e:
                logger.error(e)

        elif action == "delete":
            try:
                new_name_list = []
                has_delete_num = False

                with open(generalconf.PATH_TO_TXT_FILE, 'r') as f:
                    names_in_file = [name.rstrip() for name in f]

                with open(generalconf.PATH_TO_TXT_FILE, 'w') as f:
                    for name in names_in_file:
                        for honeypot_name in honeypot_names:
                            if name == honeypot_name:
                                has_delete_num = True
                        if not has_delete_num:
                            new_name_list.append(name)
                        has_delete_num = False

                    for name in new_name_list:
                        f.write(f"{name}\n")

            except Exception as e:
                logger.error(e)


class DataRemover:
    def deleteHoneyfilesJson():
        """Function to delete the JSON file with all honeyfiles absolute paths and it's respective hashes"""
        if os.path.exists(generalconf.PATH_TO_BUNNYSHIELD_CONFIG):
            logger.debug("Deleting honeyfile JSON.")
            try:
                os.remove(generalconf.PATH_TO_JSON_FILE)
            except FileNotFoundError:
                logger.error(f'Could not find {generalconf.HONEYFILE_JSON_ALIAS} in {generalconf.PATH_TO_BUNNYSHIELD_CONFIG}.')

    #

    def deleteHoneyfilesNamesTxt():
        """Function to delete the TXT file with all honeyfile unique names"""
        if os.path.exists(generalconf.PATH_TO_BUNNYSHIELD_CONFIG):
            logger.debug("Deleting honeyfiles name TXT.")
            try:
                os.remove(generalconf.PATH_TO_TXT_FILE)
            except FileNotFoundError:
                logger.error(f'Could not find {generalconf.HONEYFILE_NAMES_TXT_ALIAS} in {generalconf.PATH_TO_BUNNYSHIELD_CONFIG}')
