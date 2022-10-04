import os
from app.data_handler import DataUpdater


if __name__ == "__main__":
    # Modules imports
    import psutil
    import logging
    from colorama import init
    from termcolor import colored

    # Files imports
    from utils.logger import logger
    from app.audit_handler import Audit
    from app.honey_handler import HoneyHandler
    from app.file_monitor_handler import FileMonitor
    from app.config_handler import setData
    from app.config_handler import GeneralConfig as generalconf
    from app.config_handler import HoneyConfig as honeyconf
    from app.config_handler import FileMonitorConfig as monitorconf
    from app.data_handler import DataCreator

    # Start
    psutil.Process(generalconf.PID).nice(19)
    logging.getLogger("fpdf.fpdf").disabled = True
    logging.getLogger("watchdog.observers.inotify_buffer").disabled = True

    # Print welcome text
    init()
    print(colored('BunnyShield', 'blue'))
    print(colored(f'A Ransomware Detector by Bash Bunny Group  ---  version 1.0.0 for {colored("LINUX", "blue")}', 'magenta'))
    logger.debug("Starting BunnyShield Protection.")

    # Turn Audit service on
    Audit.setStatus("on")

    # Honey Handler
    # Create Honeyfolder and Honeyfiles
    if os.path.exists(generalconf.PATH_TO_BUNNYSHIELD_CONFIG_JSON):
        setData()

    if not monitorconf.SKIP_TO_MONITOR:
        if honeyconf.HONEY_ACTION == 'create':
            DataCreator.checkAndCreateConfigFolder()
            DataCreator.checkAndCreateDataFolder()
            DataCreator.createConfigFile()
            HoneyHandler.checkAndCreateHoneyFolder()
            HoneyHandler.checkAndCreateWhitelistedFolder()
            HoneyHandler.createHoneyFiles()
            FileMonitor.start()

        # Delete Honeyfolder and Honeyfiles
        elif honeyconf.HONEY_ACTION == 'delete':
            DataCreator.checkAndCreateConfigFolder()
            HoneyHandler.deleteHoneyFolder()
            HoneyHandler.deleteHoneyFiles()

    elif monitorconf.SKIP_TO_MONITOR:
        if DataUpdater.checkForHoneyFilesJsonIntegrity() == True:
            FileMonitor.start()
        else:
            HoneyHandler.deleteHoneyFiles()
            HoneyHandler.createHoneyFiles()
            FileMonitor.start()

    # Quit
    logger.debug("Quitting BunnyShield.")
