# Module Imports
import hashlib
import os
import pathlib
import re
from threading import Thread
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# File Imports
from utils.logger import logger
from app.process_handler import ProcessHandler
from app.data_handler import DataCreator, DataUpdater
from utils.helper import randomString
from app.config_handler import GeneralConfig as generalconf
from app.config_handler import HoneyConfig as honeyconf
from app.config_handler import FileMonitorConfig as monitorconf
from app.config_handler import RegexConfig as regexconf


class FileMonitor:
    def start():
        global monitor_handler
        monitor_handler = MonitorHandler()
        monitor_handler.run()


class MonitorHandler:
    def __init__(self):
        # Has changes
        self.has_create_changes = False
        self.has_update_changes = False
        self.has_delete_changes = False

        # Temp honeyfiles to take some action
        self.honeyfiles_to_create = []
        self.honeyfiles_to_update = []
        self.honeyfiles_to_delete = []
        self.temp_honeyfile_name_list = []

        # JSON and TXT data
        self.json_data = DataUpdater.getHoneyfileJsonData()
        self.txt_data = DataUpdater.getHoneyfileTxtData()

        # Misc
        self.start_protection_time = time.time()
        self.started = False

    #

    def run(self):
        """Function to run the file monitor"""
        observers = []
        observer = Observer()
        event_handler = EventHandler()

        for directory in honeyconf.DIRECTORIES:
            observer.schedule(event_handler, directory, recursive=True)
            observers.append(observer)

        observer.start()

        try:
            current_time = time.time()
            while True:
                if not self.started:
                    if (time.time() - self.start_protection_time) > 5:
                        logger.debug('File Monitor has started.')
                        logger.debug(f'Currently monitoring {len(honeyconf.DIRECTORIES)} directories.')
                        self.started = True

                new_time = time.time() - current_time
                if new_time > monitorconf.FILE_UPDATE_TIME:
                    logger.debug('Checking for honeyfiles updates.')
                    self.updateAllData()
                    self.checkForChangesAndUpdate()
                    current_time = time.time()

                continue

        except KeyboardInterrupt or SystemExit:
            logger.debug("Stopping File Monitor.")
            for observer in observers:
                observer.unschedule_all()
                observer.stop()
                observer.join()
            self.updateAllData()
            logger.debug("Updating Honeypots JSON file before exit.")

        except Exception as e:
            logger.error(e)

    #

    def updateAllData(self):
        """Function to update all data from the JSON and the TXT"""
        self.json_data = DataUpdater.getHoneyfileJsonData()
        self.txt_data = DataUpdater.getHoneyfileTxtData()

    #

    def checkForChangesAndUpdate(self):
        """Function to check if any changes are peding and then apply it"""
        if self.has_create_changes:
            DataUpdater.updateCreate(self.honeyfiles_to_create, self.honeyfiles_to_update, self.json_data)
            self.updateAllData()
            self.has_create_changes = False
            self.honeyfiles_to_create = []

        if self.has_update_changes:
            DataUpdater.updateMoveOrRename(self.honeyfiles_to_update, self.json_data)
            self.updateAllData()
            self.has_update_changes = False
            self.honeyfiles_to_update = []
            self.temp_honeyfile_name_list = []

        if self.has_delete_changes:
            DataUpdater.updateDelete(self.honeyfiles_to_delete, self.json_data)
            self.updateAllData()
            self.has_delete_changes = False
            self.honeyfiles_to_delete = []


class EventHandler(FileSystemEventHandler):
    def __init__(self):
        # Event counter
        self.created_event_count = 0
        self.moved_event_count = 0
        self.modified_event_count = 0
        self.deleted_event_count = 0
        self.check_key_file_event_count = 0
        self.honey_folder_edit_event_count = 0
        self.unknow_extension_event_count = 0
        self.honeyfile_modified_event_count = 0
        self.honeyfile_deleted_event_count = 0
        self.folder_with_honeyfiles_deleted_event_count = 0

        # Time stamps
        self.created_current_time = time.time()
        self.moved_current_time = time.time()
        self.modified_current_time = time.time()
        self.deleted_current_time = time.time()
        self.check_key_file_current_time = time.time()
        self.update_data_folder_current_time = time.time()
        self.honey_folder_edit_current_time = time.time()

        # Misc
        self.key_dict_list = []
        self.has_found_key_update = False
        self.check_ransom = False
        self.verbose = False

    #

    def on_created(self, event):
        if self.verbose:
            logger.debug("Created: " + event.src_path)

        if not honeyconf.PATH_TO_WHITELISTED_FOLDER in event.src_path:
            if os.path.isdir(event.src_path):
                self.checkForNewHoneyfileCreate(event.src_path)

            else:
                self.created_event_count += 1

                self.checkForKeyFile(event.src_path)

                while not self.check_ransom:
                    self.checkForHoneyfolderEdit(event.src_path, 'created')
                    self.checkForUnknowExt(event.src_path)
                    self.checkEventCount('created')
                    break

                if self.check_ransom:
                    self.callProcessHandler()

    #

    def on_moved(self, event):
        if self.verbose:
            logger.debug("Moved: " + event.src_path)
            logger.debug("Moved: " + event.dest_path)

        if not honeyconf.PATH_TO_WHITELISTED_FOLDER in event.src_path or not honeyconf.PATH_TO_WHITELISTED_FOLDER in event.dest_path:
            self.moved_event_count += 1

            self.checkForHoneyfileMove(event.src_path, event.dest_path)
            while not self.check_ransom:
                self.checkEventCount('moved')
                break

            if self.check_ransom:
                self.callProcessHandler()

    #

    def on_modified(self, event):
        if self.verbose:
            logger.debug("Modified: " + event.src_path)

        if not honeyconf.PATH_TO_WHITELISTED_FOLDER in event.src_path:
            self.modified_event_count += 1

            while not self.check_ransom:
                self.checkForHoneyfolderEdit(event.src_path, 'modified')
                self.checkHoneyfileHash(event.src_path)
                self.checkEventCount('modified')
                break

            if self.check_ransom:
                self.callProcessHandler()

    #

    def on_deleted(self, event):
        if self.verbose:
            logger.debug("Deleted: " + event.src_path)

        if not honeyconf.PATH_TO_WHITELISTED_FOLDER in event.src_path:
            self.deleted_event_count += 1

            while not self.check_ransom:
                self.checkForHoneyfolderEdit(event.src_path, 'deleted')
                self.checkForHoneyfileDelete(event.src_path)
                self.checkEventCount('deleted')
                break

            if self.check_ransom:
                self.callProcessHandler()

    #
    # Specific Events Handler

    def checkForKeyFile(self, event_path):
        """Function to check if a file with some sort of key extension was created, and then get the key data and save in the BunnyShield data folder"""
        update_time = time.time() - self.update_data_folder_current_time
        update_data_folder = False
        if update_time > 30:
            update_data_folder = True

        if generalconf.PATH_TO_BUNNYSHIELD_DATA not in event_path:
            file_name = re.findall(regexconf.FILE_IN_PATH_PATTERN, event_path)[0]
            file_ext = str(pathlib.Path(file_name).suffix)

            if file_ext in generalconf.KEY_EXT_LIST:
                new_time = time.time() - self.check_key_file_current_time
                print(new_time)
                self.check_key_file_event_count += 1

                if os.path.exists(event_path):
                    with open(event_path, 'rb') as f:
                        key_dict = {
                            "absolute_path": event_path,
                            "data": f.read()
                        }
                    self.key_dict_list.append(key_dict)
                    self.has_found_key_update = True
                    self.check_key_file_current_time = time.time()

                if new_time > 5 and self.has_found_key_update:
                    logger.warning(f"Found a key file in {event_path}{'.' if self.check_key_file_event_count <= 1 else ' (and ' + str(self.check_key_file_event_count) + ' more)'}.")

        if update_data_folder:
            for dict in self.key_dict_list:
                key_folder_name = str(round(time.time())) + '-key-' + randomString('unique-name')
                os.mkdir(os.path.join(generalconf.PATH_TO_BUNNYSHIELD_DATA, key_folder_name))

                key_file_name = re.findall(regexconf.FILE_IN_PATH_PATTERN, dict['absolute_path'])[0]
                with open(os.path.join(generalconf.PATH_TO_BUNNYSHIELD_DATA, key_folder_name, key_file_name), 'wb') as f:
                    f.write(dict['data'])

            self.has_found_key_update = False
            self.key_dict_list = []

    def checkForNewHoneyfileCreate(self, event_path):
        """Function to check if the event path is a directory and if should be created a new honeyfile"""
        try:
            for _, folders_in_current_path, _ in os.walk(event_path, topdown=True):
                if len(folders_in_current_path) == 0:
                    new_honeyfile_dict, honeyfile_name = DataCreator.createSingleHoneyfile(event_path)
                    monitor_handler.temp_honeyfile_name_list.append(honeyfile_name)
                    monitor_handler.honeyfiles_to_create.append(new_honeyfile_dict)
                    monitor_handler.has_create_changes = True
            folders_in_current_path.clear()

        except:
            pass

    #

    def checkForHoneyfolderEdit(self, event_path, event_action):
        """Function to check if any PDF inside the honeyfolder was edited in any way"""
        if honeyconf.PATH_TO_HONEYFOLDER in event_path:
            new_time = time.time() - self.honey_folder_edit_current_time
            self.honey_folder_edit_event_count += 1

            if new_time > 3:
                logger.warning(f"File {event_action} in Honeyfolder{'.' if self.honey_folder_edit_event_count <= 1 else ' (and ' + str(self.honey_folder_edit_event_count) + ' more).'}")
                self.honey_folder_edit_current_time = time.time()
                self.honey_folder_edit_event_count = 0
                self.check_ransom = True

    #

    def checkForUnknowExt(self, event_path):
        """Function to check if the file has a blank extension or a unknow extension"""
        if generalconf.PATH_TO_HOME_DOTCONFIG in event_path:
            has_blank_ext = False
            has_know_ext = False
            file_ext = str(pathlib.Path(re.findall(regexconf.FILE_IN_PATH_PATTERN, event_path)[0]).suffix)

            if file_ext == "":
                has_blank_ext = True

            if file_ext in generalconf.FILE_EXT_LIST and not has_blank_ext:
                has_know_ext = True

            if not has_know_ext or has_blank_ext:
                new_time = time.time() - self.created_current_time
                self.unknow_extension_event_count += 1

                if new_time > 3:
                    logger.warning(f"Unknow file extension detected \"{'blank extension' if has_blank_ext else file_ext}\"{'.' if self.unknow_extension_event_count <= 1 else ' (and ' + str(self.unknow_extension_event_count) + ' more).'}")

                    if self.unknow_extension_event_count > monitorconf.UNKNOW_EXTENSION_EVENT_COUNT_TRIGGER:
                        self.created_current_time = time.time()
                        self.unknow_extension_event_count = 0
                        self.check_ransom = True

    #

    def checkEventCount(self, event_action):
        """Function to check how many events from the spefic action happened in a determined space of time"""
        try:
            event_count, current_time = self.returnEventData(event_action, 'get')

            if event_count >= monitorconf.EVENT_COUNT_TRIGGER:
                new_time = time.time() - current_time

                if new_time > 10:
                    logger.warning(f"Various files {event_action} ({event_count} files).")
                    self.returnEventData(event_action, 'reset')
                    self.check_ransom = True

        except:
            pass

    #

    def returnEventData(self, event_action, action):
        """Function to return or reset the data from the event count and current time of an specific action"""
        if event_action == 'created':
            if action == 'get':
                return self.created_event_count, self.created_current_time

            if action == 'reset':
                self.created_event_count = 0
                self.created_current_time = time.time()

        if event_action == 'moved':
            if action == 'get':
                return self.moved_event_count, self.moved_current_time

            if action == 'reset':
                self.moved_event_count = 0
                self.moved_current_time = time.time()

        if event_action == 'modified':
            if action == 'get':
                return self.modified_event_count, self.modified_current_time

            if action == 'reset':
                self.modified_event_count = 0
                self.modified_current_time = time.time()

        if event_action == 'deleted':
            if action == 'get':
                return self.deleted_event_count, self.deleted_current_time

            if action == 'reset':
                self.deleted_event_count = 0
                self.deleted_current_time = time.time()

    #

    def checkForHoneyfileMove(self, event_src_path, event_dest_path):
        """Function to check if a honeyfile was moved"""
        try:
            if not os.path.isdir(event_dest_path):

                if re.findall(regexconf.FILE_IN_PATH_PATTERN, event_src_path)[0] in monitor_handler.txt_data or re.findall(regexconf.FILE_IN_PATH_PATTERN, event_src_path)[0] in monitor_handler.temp_honeyfile_name_list:

                    if re.findall(regexconf.FILE_IN_PATH_PATTERN, event_dest_path)[0] in monitor_handler.txt_data or re.findall(regexconf.FILE_IN_PATH_PATTERN, event_dest_path)[0] in monitor_handler.temp_honeyfile_name_list:

                        update_honeypot_dict = {
                            "old_path": event_src_path,
                            "new_path": event_dest_path
                        }

                        monitor_handler.honeyfiles_to_update.append(update_honeypot_dict)
                        monitor_handler.has_update_changes = True

        except:
            pass

    #

    def checkHoneyfileHash(self, event_path):
        """Function to check if a honeyfile current hash is different from the one in the JSON file"""
        try:
            if re.findall(regexconf.FILE_IN_PATH_PATTERN, event_path)[0] in monitor_handler.txt_data:
                for dict in monitor_handler.json_data:
                    if event_path == dict['absolute_path']:
                        with open(event_path, 'rb') as f:
                            file_data = f.read()
                            current_hash = hashlib.sha1(file_data).hexdigest()

                            if current_hash != dict['hash']:
                                new_time = time.time() - self.modified_current_time
                                self.honeyfile_modified_event_count += 1

                                if new_time > 3:
                                    logger.warning(f"Honeyfile was modified{'.' if self.honeyfile_modified_event_count <= 1 else '(and ' + str(self.honeyfile_modified_event_count) + ' more).'}")

                                    if self.honeyfile_modified_event_count >= monitorconf.HONEYFILE_MODIFIED_EVENT_COUNT_TRIGGER:
                                        self.modified_current_time = time.time()
                                        self.honeyfile_modified_event_count = 0
                                        self.check_ransom = True

        except:
            pass

    #

    def checkForHoneyfileDelete(self, event_path):
        """Function to check if a honeyfile or a folder with one or more honeyfiles was deleted"""
        if re.findall(regexconf.FILE_IN_PATH_PATTERN, event_path)[0] in monitor_handler.txt_data or re.findall(regexconf.FILE_IN_PATH_PATTERN, event_path)[0] in monitor_handler.temp_honeyfile_name_list:
            self.checkForDeletedHoneyfile(event_path)
        else:
            self.checkForDeletedFolderWithHoneyfile(event_path)

    #

    def checkForDeletedHoneyfile(self, event_path):
        """Function to check if a honeyfile was deleted"""
        try:
            if not os.path.exists(event_path):
                new_time = time.time() - self.deleted_current_time
                self.honeyfile_deleted_event_count += 1

                monitor_handler.honeyfiles_to_delete.append(event_path)
                monitor_handler.has_delete_changes = True

                if new_time > 3:
                    logger.warning(f"Honeyfile was deleted{'.' if self.honeyfile_deleted_event_count <= 1 else ' (and ' + str(self.honeyfile_deleted_event_count) + ' more).'}")

                    if self.honeyfile_deleted_event_count >= monitorconf.HONEYFILE_DELETED_EVENT_COUNT_TRIGGER:
                        self.deleted_current_time = time.time()
                        self.honeyfile_deleted_event_count = 0
                        self.check_ransom = True
        except:
            pass
    #

    def checkForDeletedFolderWithHoneyfile(self, event_path):
        """Function to check if a folder containing one or more honeyfiles was deleted"""
        try:
            new_time = time.time() - self.deleted_current_time
            honeypot_deleted = False

            for element in monitor_handler.json_data:
                if event_path in element['absolute_path']:
                    honeypot_deleted = True
                    break
                else:
                    continue

            for element in monitor_handler.honeyfiles_to_create:
                if event_path in element['absolute_path']:
                    honeypot_deleted = True
                    break
                else:
                    continue

            for element in monitor_handler.honeyfiles_to_update:
                if event_path in element['new_path']:
                    honeypot_deleted = True
                    break
                else:
                    continue

            for honeyfile_name in monitor_handler.temp_honeyfile_name_list:
                if honeyfile_name in event_path:
                    honeypot_deleted = True
                    break
                else:
                    continue

            if honeypot_deleted:
                self.folder_with_honeyfiles_deleted_event_count += 1

                monitor_handler.honeyfiles_to_delete.append(event_path)
                monitor_handler.has_delete_changes = True

                if new_time > 3:
                    logger.debug(f"Folder with honeyfiles was deleted{'.' if self.folder_with_honeyfiles_deleted_event_count <= 1 else ' (and ' + str(self.folder_with_honeyfiles_deleted_event_count) + ' more).'}")

                    if self.folder_with_honeyfiles_deleted_event_count > monitorconf.FOLDER_WITH_HONEYFILES_DELETED_EVENT_COUNT_TRIGGER:
                        self.deleted_current_time = time.time()
                        self.folder_with_honeyfiles_deleted_event_count = 0
                        self.check_ransom = True

        except:
            pass

    #

    def callProcessHandler(self):
        """Function to call the Process Handler and check for Ransomware"""
        threads = []
        proc_handler = ProcessHandler()
        th = Thread(target=proc_handler.checkForRansomware)
        th.start()
        threads.append(th)

        for th in threads:
            try:
                th.join()
            except:
                pass

        self.check_ransom = False
