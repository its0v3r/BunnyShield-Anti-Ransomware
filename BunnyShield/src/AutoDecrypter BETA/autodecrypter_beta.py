#!/usr/bin/env python
import os
import re
import subprocess
import time
import pyinotify


class MyEventHandler(pyinotify.ProcessEvent):
    def __init__(self):
        self.recent_opened_files_dict_list = []
        self.pathname_list = []
        self.timeout = time.time() + 60
        self.decrypt = False

    def process_IN_OPEN(self, event):
        try:
            if not event.dir:
                if (time.time() - os.path.getmtime(event.pathname) > 10):
                    print(f'[{len(self.recent_opened_files_dict_list)}] Saving {event.pathname}')
                    if event.pathname not in self.pathname_list:
                        self.pathname_list.append(event.pathname)
                        with open(event.pathname, 'rb') as f:
                            file_dict = {
                                "path": event.pathname,
                                "bytes": f.read(),
                                "file_perm": subprocess.check_output([f'stat -c %a "{event.pathname}"'], shell=True, stderr=subprocess.DEVNULL).decode().strip()
                            }
                            self.recent_opened_files_dict_list.append(file_dict)

            if len(self.recent_opened_files_dict_list) >= 10001:
                self.recent_opened_files_dict_list.pop(0)

            if time.time() > self.timeout and not self.decrypt:
                self.decryptfiles()

        except:
            pass

    def decryptfiles(self):
        print(f'Decrypting {len(self.recent_opened_files_dict_list)} files.')
        self.decrypt = True

        FILE_IN_PATH_PATTERN = "([^\/]+$)"
        for dict in self.recent_opened_files_dict_list:
            file_name = re.findall(FILE_IN_PATH_PATTERN, dict['path'])[0]

            with open(os.path.join(BACKUP_FOLDER, file_name), 'wb') as f:
                f.write(dict['bytes'])

        for dict in self.recent_opened_files_dict_list:
            file_name = re.findall(FILE_IN_PATH_PATTERN, dict['path'])[0]

            with open(os.path.join(dict['path']), 'wb') as f:
                f.write(dict['bytes'])
            subprocess.check_output([f"chmod {dict['file_perm']} \"{dict['path']}\""], shell=True, stderr=subprocess.DEVNULL)

        print(f'Decrypted {self.self.recent_opened_files_dict_list} files.')
        self.recent_opened_files_dict_list = []
        if not self.recent_opened_files_dict_list:
            quit()


def main():
    print(os.getpid())
    global BACKUP_FOLDER
    BACKUP_FOLDER = os.path.join("/home/matheusheidemann", 'Decrypted Files Folder')
    try:
        os.mkdir(BACKUP_FOLDER)
    except:
        pass
    wm = pyinotify.WatchManager()
    flag = pyinotify.EventsCodes.FLAG_COLLECTIONS['OP_FLAGS']['IN_OPEN']
    #wm.add_watch('/etc/', flag, rec=True)
    wm.add_watch('/home/matheusheidemann', flag, rec=True)

    eh = MyEventHandler()

    notifier = pyinotify.Notifier(wm, eh)
    print('Decrypter has started.')
    notifier.loop()


if __name__ == '__main__':
    main()
