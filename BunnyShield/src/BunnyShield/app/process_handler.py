# Module imports
import os
import pathlib
import re
from threading import Thread
import time
import psutil
import subprocess

# File imports
from utils.logger import logger
from app.config_handler import GeneralConfig as generalconf
from app.config_handler import RegexConfig as regexconf
from app.config_handler import AuditConfig as auditconf
from app.config_handler import ProcessHandlerConfig as processconf
from utils.helper import tableToDict, isHexStr, decodeHex


class ProcessHandler():
    def __init__(self):
        self.start = time.perf_counter()
        self.malicious_process_killed = False
        self.malicious_pids = []
        self.process_has_cwd = False

    #

    def checkForRansomware(self):
        """Function to try to kill the malicious process"""
        logger.debug("Scanning for Ransomware.")
        try:
            if not self.malicious_process_killed:
                self.tryKillProcessByFileChangeEvent()
        except:
            pass

        try:
            if not self.malicious_process_killed:
                self.tryKillProcessByOpenedShellEvent()
        except:
            pass
    #

    def tryKillProcessByFileChangeEvent(self):
        """Function to try to kill the malicious process by the file system edit events"""
        threads = []
        dir_changes_events = subprocess.check_output([f"ausearch -k {auditconf.FILE_EVENT_RULE_NAME} | tail -n {processconf.MAX_TAIL_FOR_DIR_CHANGES_EVENT}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-10:]

        for event in dir_changes_events:
            try:
                # Check if the process has a terminal attached to it
                if re.findall(regexconf.TTY_PATTERN, event)[0] != "(none)":

                    # Try get the Ransomware file path
                    try:
                        process_cwd = re.findall(regexconf.CWD_PATH_PATTERN, event)[0]

                        if isHexStr(process_cwd):
                            process_cwd = decodeHex(process_cwd)

                        if generalconf.PATH_TO_BUNNYSHIELD in process_cwd:
                            self.process_has_cwd = True

                    except Exception as e:
                        # logger.error(e)
                        pass

                    try:
                        # Get PIDs of process and validate
                        for pid in re.findall(regexconf.PID_PATTERN, event):
                            pid = int(pid)

                            if pid != 1 and pid != generalconf.PID and pid != generalconf.PPID and pid not in self.malicious_pids:
                                psutil.Process(pid).status()
                                self.malicious_pids.append(pid)

                                th = Thread(target=self.validateAndKillProcess, args=[pid, '1'])
                                th.start()
                                threads.append(th)

                    except Exception as e:
                        # logger.error(e)
                        pass

            except:
                pass

        for th in threads:
            try:
                th.join()
            except:
                pass
    #

    def tryKillProcessByOpenedShellEvent(self):
        """Function to try to kill the malicious process by the opened shell events"""
        threads = []
        shell_open_events = subprocess.check_output([f"ausearch -l -k {auditconf.FILE_OPEN_SHELL_RULE_NAME} | tail -n {processconf.MAX_TAIL_FOR_SHELL_OPEN_EVENT}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().split("----")[-10:]

        for event in reversed(shell_open_events):
            try:
                # Check if the process has a terminal attached to it
                if re.findall(regexconf.TTY_PATTERN, event)[0] != "(none)":

                    # Try get the Ransomware file path
                    try:
                        process_cwd = re.findall(regexconf.CWD_PATH_PATTERN, event)[0]

                        if isHexStr(process_cwd):
                            process_cwd = decodeHex(process_cwd)

                        if generalconf.PATH_TO_BUNNYSHIELD not in process_cwd:
                            self.process_has_cwd = True

                    except:
                        pass

                    try:
                        for pid in re.findall(regexconf.PID_PATTERN, event):
                            pid = int(pid)

                            if pid != 1 and pid != generalconf.PID and pid != generalconf.PPID and pid not in self.malicious_pids:
                                psutil.Process(pid).status()
                                self.malicious_pids.append(pid)

                                th = Thread(target=self.validateAndKillProcess, args=[pid, '2'])
                                th.start()
                                threads.append(th)

                    except:
                        pass

            except:
                pass

        for th in threads:
            try:
                th.join()
            except:
                pass
    #

    def validateAndKillProcess(self, pid, method):
        """Function to check and kill the malicious process"""

        if self.isPotentialMaliciousProcess(pid):
            try:
                malicious_pid = pid
                logger.critical(f"Ransomware process with PID {malicious_pid}. Killing it.")

                if self.process_has_cwd:
                    process_file_abs_path_list, original_dir_permissions, process_cwd = self.tryGetMaliciousCWD(malicious_pid)
                    self.tryKillRansomwareProcess(malicious_pid, method)
                    self.tryDeleteMaliciousFile(process_file_abs_path_list, original_dir_permissions, process_cwd)

                else:
                    self.tryKillRansomwareProcess(malicious_pid, method)

            except Exception as e:
                # logger.error(e)
                pass
        else:
            return

    #

    def isPotentialMaliciousProcess(self, pid):
        """Function to check if the process behaves like a ransomware"""
        logger.debug(f"Validating process {pid} - 4+ flags means bad behaviour.")

        # Monitor Syscalls for 2 secs
        try:
            cmd = f"timeout --preserve-status --foreground 1 strace -c --trace=openat,open,close,read,write,epoll_ctl,unlink,unlinkat --summary-columns=calls,name -f -p {pid}"
            _, out = subprocess.getstatusoutput(cmd)
            syscall_dict_list = tableToDict(out)

            has_open_call = False
            has_write_call = False
            has_delete_call = False
            malicious_flags_counter = 0

            for dict in syscall_dict_list:
                if dict['syscall'] == 'lseek':
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1

                elif dict['syscall'] == 'open' and not has_open_call:
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1
                        has_open_call = True

                elif dict['syscall'] == 'openat' and not has_open_call:
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1
                        has_open_call = True

                elif dict['syscall'] == 'close':
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1

                elif dict['syscall'] == 'read':
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1

                elif dict['syscall'] == 'write' and not has_write_call:
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1
                        has_write_call = True

                elif dict['syscall'] == 'epoll_ctl' and not has_write_call:
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1
                        has_write_call = True

                elif dict['syscall'] == 'unlink' and not has_delete_call:
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1
                        has_delete_call = True

                elif dict['syscall'] == 'unlinkat' and not has_delete_call:
                    if int(dict['count']) > 1:
                        malicious_flags_counter += 1
                        has_delete_call = True

        except Exception as e:
            # logger.error(e)
            pass

        # Monitor IO for 1 sec
        try:
            process = psutil.Process(pid)
            start_bytes = process.io_counters().write_bytes
            time.sleep(1)
            final_bytes = process.io_counters().write_bytes

            if (final_bytes - start_bytes) > 100000:
                malicious_flags_counter += 1
            else:
                pass

        except Exception as e:
            # logger.error(e)
            pass

    #

        if malicious_flags_counter >= 4:
            logger.critical(f"Process validated with PID {pid} - {malicious_flags_counter} flags.")
            return True
        else:
            logger.debug(f"Process validated with PID {pid} - {malicious_flags_counter} flags")
            return False

    #

    def tryGetMaliciousCWD(self, malicious_pid):
        """Function to try to get the path to the ransomware file, the ransomware current working directory and it's current permisions"""
        try:
            process_cwd = psutil.Process(malicious_pid).cwd()
            process_cmdline_list = psutil.Process(malicious_pid).cmdline()
            process_file_abs_path_list = self.getRansomwarePath(process_cwd, process_cmdline_list)

        except Exception as e:
            # logger.error(e)
            pass

        try:
            has_a_file_in_cwd = False
            if process_file_abs_path_list:
                for path in process_file_abs_path_list:
                    if os.path.isfile(path):
                        has_a_file_in_cwd = True

            elif not process_file_abs_path_list or not has_a_file_in_cwd:
                malicious_ppid = malicious_pid
                process_cwd = psutil.Process(malicious_ppid).cwd()
                process_cmdline_list = psutil.Process(malicious_ppid).cmdline()
                process_file_abs_path_list = self.getRansomwarePath(process_cwd, process_cmdline_list)

        except Exception as e:
            # logger.error(e)
            pass

        original_dir_permissions = subprocess.check_output([f'stat -c %a "{process_cwd}"'], shell=True, stderr=subprocess.DEVNULL).decode().strip()
        subprocess.check_output([f'chmod a-x "{process_cwd}"'], shell=True, stderr=subprocess.DEVNULL)

        return process_file_abs_path_list, original_dir_permissions, process_cwd

    #

    def getRansomwarePath(self, malicious_cwd, cmdline_list):
        """Function to get the ransomware file path"""
        malicious_cwd_list = []
        file_name = 'NO-FILE-DETECTED'

        for cmdline in cmdline_list:
            try:
                file_ext = str(pathlib.Path(cmdline).suffix)
                if file_ext in generalconf.FILE_EXT_LIST:
                    file_name = cmdline
                final_cwd = os.path.join(malicious_cwd, file_name)

                if os.path.exists(final_cwd):
                    if malicious_cwd in final_cwd:
                        malicious_cwd_list.append(final_cwd)

            except Exception as e:
                # logger.error(e)
                pass

            try:
                item_path = re.findall(regexconf.MALICIOUS_FILE_PATH_PATTERN, cmdline)[0]
                final_cwd = os.path.join(malicious_cwd, item_path)

                if os.path.exists(final_cwd):
                    if malicious_cwd in final_cwd:
                        malicious_cwd_list.append(final_cwd)

            except Exception as e:
                # logger.error(e)
                pass

            try:
                if os.path.isfile(cmdline):
                    if malicious_cwd in cmdline:
                        malicious_cwd_list.append(cmdline)

            except Exception as e:
                # logger.error(e)
                pass

        if malicious_cwd_list:
            return list(dict.fromkeys(malicious_cwd_list))
        else:
            return []

    #
    def tryKillRansomwareProcess(self, malicious_pid, method):
        """Function to try to kill the ransomware PID and it's PPID"""
        killed = False
        malicious_ppid = psutil.Process(malicious_pid).ppid()

        # Kill PID
        try:
            subprocess.check_output([f"kill -9 {malicious_pid}"], shell=True, stderr=subprocess.DEVNULL)
            killed = True
        except Exception as e:
            # logger.error(e)
            pass

        # Kill PPID
        try:
            subprocess.check_output([f"kill -9 {malicious_ppid}"], shell=True, stderr=subprocess.DEVNULL)
            killed = True
        except Exception as e:
            # logger.error(e)
            pass

        if killed:
            logger.critical(f"Killed ransomware process with PID {malicious_pid} and PPID {malicious_ppid} - [Code {method}].")
            end = time.perf_counter()
            logger.critical(f"Successfully stopped ransomware in {round(end - self.start, 3)}s.")
            self.malicious_process_killed = True

    #

    def tryDeleteMaliciousFile(self, process_file_abs_path_list, original_dir_permissions, process_cwd):
        """Function to try to delete the ransomware file"""
        for path in process_file_abs_path_list:
            logger.critical(f"Ransomware file is in {path}. Deleting it.")
            try:
                os.remove(path)
                logger.critical(f"Successfully deleted ransomware file in {path}.")

                pass
            except:
                pass

            if process_file_abs_path_list:
                subprocess.check_output([f'chmod {original_dir_permissions} "{process_cwd}"'], shell=True, stderr=subprocess.DEVNULL)

            else:
                logger.critical(f"Could not find the specific ransomware file, but it is in {process_cwd}. The folder is currently locked and the ransomware should not execute itself again, but it's higly advisible to find and delete the malicious file.")
