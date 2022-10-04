# Module imports
import json
import os
import pathlib
import re
import subprocess
import time

# Files imports
from utils.logger import logger
from app.audit_handler import Audit
from utils.helper import generatePDFs, randomString
from app.config_handler import GeneralConfig as generalconf
from app.config_handler import HoneyConfig as honeyconf
from app.config_handler import RegexConfig as regexconf
from app.data_handler import DataCreator, DataRemover


class HoneyHandler:

    def checkAndCreateHoneyFolder():
        """Function to create the Honeyfolder with PDFs"""
        start = time.perf_counter()

        if not os.path.exists(honeyconf.PATH_TO_HONEYFOLDER):
            logger.debug(f"Creating honeyfolder in {honeyconf.PATH_TO_HONEYFOLDER}.")

            os.mkdir(honeyconf.PATH_TO_HONEYFOLDER)

            generatePDFs()
            subprocess.check_output([f'chmod a+w -R "{honeyconf.PATH_TO_HONEYFOLDER}"'], shell=True, stderr=subprocess.DEVNULL)
            subprocess.check_output([f'chown -R {generalconf.USER} "{honeyconf.PATH_TO_HONEYFOLDER}"'], shell=True, stderr=subprocess.DEVNULL)

            end = time.perf_counter()
            logger.debug(f"Finished creating honeyfolder in {round(end - start, 3)}s.")
        else:
            logger.debug(f"Honeyfolder already exists in {honeyconf.PATH_TO_HONEYFOLDER}. It will not be created a new one.")

    #

    def deleteHoneyFolder():
        """Function to delete the Honeyfolder with PDFs"""
        start = time.perf_counter()

        if os.path.exists(honeyconf.PATH_TO_HONEYFOLDER):
            logger.debug(f"Deleting honeyfolder in {honeyconf.PATH_TO_HONEYFOLDER}.")
            for current_path, _, files_in_current_path in os.walk(honeyconf.PATH_TO_HONEYFOLDER):
                try:
                    if os.access(current_path, os.W_OK):
                        for file in files_in_current_path:
                            file_absolute_path = os.path.join(current_path, file)
                            os.remove(file_absolute_path)

                except Exception as e:
                    logger.error(e)
                    continue

            os.rmdir(honeyconf.PATH_TO_HONEYFOLDER)

            end = time.perf_counter()
            logger.debug(f"Finished deleting honeyfolder in {round(end - start, 3)}s.")

        else:
            logger.debug(f"Could not find honeyfolder in {honeyconf.PATH_TO_HONEYFOLDER}.")

    #

    def createHoneyFiles():
        """Function to create the Honeyfiles in the desired directories"""

        all_honeyfiles_names_list = []
        honeyfiles_dict_list = []

        Audit.createCustomRuleFile()

        for directory in honeyconf.DIRECTORIES:
            start = time.perf_counter()
            paths_to_generate_honeyfiles = []

            for current_path, folders_in_current_path, _ in os.walk(directory):

                if not generalconf.PATH_TO_BUNNYSHIELD in current_path or not honeyconf.PATH_TO_WHITELISTED_FOLDER in current_path:
                    if len(folders_in_current_path) == 0:
                        paths_to_generate_honeyfiles.append(current_path)

                    elif str(pathlib.Path(re.findall(regexconf.PATH_WITHOUT_FILE_PATTERN, current_path)[0])) == directory:
                        paths_to_generate_honeyfiles.append(current_path)

                    elif current_path == directory:
                        paths_to_generate_honeyfiles.append(current_path)

            logger.debug(f"Creating a total of {len(paths_to_generate_honeyfiles)} honeyfiles in {directory}")
            for current_path in paths_to_generate_honeyfiles:
                try:
                    if os.access(current_path, os.W_OK):
                        honeyfile_name = honeyconf.HONEYFILE_PREFIX + randomString("unique-name") + '.txt'
                        all_honeyfiles_names_list.append(honeyfile_name)
                        honeyfile_absolute_path = os.path.join(current_path, honeyfile_name)

                        # Create Honeypot file
                        with open(honeyfile_absolute_path, 'w') as f:
                            f.write("THIS IS A BUNNYSHIELD FILE! PLEASE, DO NOT MOVE, DELETE, RENAME OR MODIFY THIS FILE! YOU ARE STILL FREE TO MOVE ANY FOLDER THAT CONTAINS A FILE LIKE THIS.\n")
                            f.write(f"Credit card details: {randomString('unique-number')}")

                        # Create Honeypot dict
                        with open(honeyfile_absolute_path, 'rb') as f:
                            honeyfiles_dict_list.append(DataCreator.createHoneyfileDataDict(f))

                        # Change honeyfile permissions
                        subprocess.check_output([f'chmod 666 "{honeyfile_absolute_path}"'], shell=True, stderr=subprocess.DEVNULL)
                        subprocess.check_output([f'chown {generalconf.USER} "{honeyfile_absolute_path}"'], shell=True, stderr=subprocess.DEVNULL)

                except:
                    pass

            end = time.perf_counter()
            logger.debug(f"Finished creating honeyfiles in {directory} in {round(end - start, 3)}s.")
            Audit.createAuditRule(directory)

        Audit.loadRules()
        DataCreator.createHoneyfilesJson(honeyfiles_dict_list)
        DataCreator.createHoneyfilesNamesTxt(all_honeyfiles_names_list)

    #

    def deleteHoneyFiles():
        """Function to delete the Honeyfiles"""
        try:
            json_paths_list = []

            with open(generalconf.PATH_TO_JSON_FILE) as f:
                json_file = json.load(f)
                for dict in json_file:
                    if dict['absolute_path']:
                        json_paths_list.append(dict['absolute_path'])

        except FileNotFoundError:
            logger.error(f'Could not find {generalconf.HONEYFILE_JSON_ALIAS} in {generalconf.PATH_TO_BUNNYSHIELD_CONFIG}. The agressive delete mode will be used.')

        start = time.perf_counter()
        deleted_count = 0

        for directory in honeyconf.DIRECTORIES:
            logger.debug(f"Deleting honeypots in {directory}.")
            for current_path, _, files_in_current_path in os.walk(directory):
                try:
                    if os.access(current_path, os.W_OK):
                        for file in files_in_current_path:
                            if honeyconf.HONEYFILE_PREFIX in file:
                                file_absolute_path = os.path.join(current_path, file)
                                os.remove(file_absolute_path)
                                deleted_count += 1

                except Exception as e:
                    logger.error(e)
                    continue

            if deleted_count == 0:
                logger.debug(f"No honeyfiles where found to be deleted.")
            else:
                logger.debug(f"Finished deleting a total of {deleted_count} honeyfiles in {directory}.")

        end = time.perf_counter()
        logger.debug(f"Finished deleting all honeyfiles in {round(end - start, 3)}s.")

        Audit.deleteCustomRuleFile()
        Audit.deleteRules()
        DataRemover.deleteHoneyfilesJson()
        DataRemover.deleteHoneyfilesNamesTxt()

    #

    def checkAndCreateWhitelistedFolder():
        """Function to create the Whitelisted Folder"""
        start = time.perf_counter()

        if not os.path.exists(honeyconf.PATH_TO_HONEYFOLDER):
            logger.debug(f"Creating a whitelisted folder in {honeyconf.PATH_TO_WHITELISTED_FOLDER}.")
            os.mkdir(honeyconf.PATH_TO_WHITELISTED_FOLDER)
            end = time.perf_counter()
            logger.debug(f"Finished creating whitelisted folder in {round(end - start, 3)}s.")
        else:
            logger.debug(f"Whitelisted already exists in {honeyconf.PATH_TO_WHITELISTED_FOLDER}. It will not be created a new one.")
