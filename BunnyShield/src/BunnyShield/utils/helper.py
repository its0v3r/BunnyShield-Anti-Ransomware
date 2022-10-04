import hashlib
import json
import os
import random
import string
from utils.logger import logger
from app.config_handler import HoneyConfig as hc
from fpdf import FPDF


def randomString(action):
    """Function to generate a ransom hash or string"""
    if action == "unique-hash":
        characters = string.ascii_letters + string.digits + string.punctuation
        random_string = ''.join(random.choice(characters) for i in range(50))
        return random_string

    if action == "unique-name":
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for i in range(25))
        return random_string

    if action == "unique-number":
        characters = string.digits
        random_string = ''.join(random.choice(characters) for i in range(50))
        return random_string


def generatePDFs():
    """Function to generate 10.000 random PDF honeyfiles"""
    for i1 in range(0, 100):
        for i2 in range(0, 100):
            word = random.choice(hc.RANDOM_WORDS)
            unique_pdf = FPDF()
            unique_pdf.add_page()
            unique_pdf.set_font('Arial', 'B', 8)
            unique_pdf.cell(40, 10, f'{word}: {i1} - {i2}')
            unique_pdf.output(os.path.join(hc.PATH_TO_HONEYFOLDER, f'{word}-{i1}-{i2}.pdf'), 'F')


def tableToDict(table):
    """Function to convert the strace syscall table to a dictonary"""
    ignore = ["---", "strace", "calls", "total"]
    lines = table.strip().split('\n')
    syscall_list = []

    try:
        for line in lines:
            temp_dict = {}
            if any(x in line for x in ignore):
                pass
            else:
                temp_dict = {
                    "syscall": line.split()[1],
                    "count": line.split()[0],
                }
                syscall_list.append(temp_dict)

        return syscall_list

    except Exception as e:
        # logger.error(e)
        pass

#


def isHexStr(s):
    try:
        return set(s).issubset(string.hexdigits)
    except:
        pass

#


def decodeHex(s):
    try:
        return bytes.fromhex(s).decode("ascii")
    except:
        pass
