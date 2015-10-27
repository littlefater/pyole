#!/usr/bin/env python
"""
pyole example: filter out samples based on strings in VBA

currently support files in following format:
* ole format
* openxml format
* mhtml format
* base64 encoded mhtml format
"""

import os
import re
import sys
import time
import zlib
import shutil
import base64
import zipfile
import hashlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pyvba import *

def check_vba(filename, sig_list):

    try:
        vbafile = VBAFile(filename)

        vba_code = ''
        for ModuleRecord in vbafile.dir.ModulesRecord.ModuleArray:
            codepage = 'cp' + str(vbafile.dir.InformationRecord.CodePageRecord.CodePage)
            code = vbafile.OLE.find_object_by_name(ModuleRecord.NameRecord.ModuleName.decode(codepage))[ModuleRecord.OffsetRecord.TextOffset:]
            vba_code += vbafile._decompress(code)
        
        for sig in sig_list:
            if -1 == vba_code.find(sig):
                return False

        return True    
            
    except Exception as e:
        print os.path.basename(filename) + ': ' + str(e)

    return False


def parse_files(filedir, sig_list, action):

    if action:
        out_dir = 'flt_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
        os.makedirs(out_dir)

    for root, dirs, files in os.walk(filedir):
        for file in files:
            filename = os.path.join(root, file)

            ole_file = extract_ole_file(filename)
            if ole_file is not None:
                result = check_vba(ole_file, sig_list)
                if ole_file[0x00:0x07] == 'tmpole_':
                    os.remove(ole_file)
                if result:
                    print file
                    if 1 == action:
                        newfile = os.path.join(out_dir, file)
                        shutil.copy2(filename, newfile)
                    elif 2 == action:
                        newfile = os.path.join(out_dir, file)
                        shutil.move(filename, newfile)
            else: 
                print file + ': Unsupport file format.'


def extract_ole_file(filename):

    data = open(filename, 'rb').read()
    tmp_file = 'tmpole_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))

    if data[0x00:0x08] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
        return filename
    
    if data[0x00:0x04] == '\x50\x4b\x03\x04':
        try:
            zf = zipfile.ZipFile(filename, 'r')
            for name in zf.namelist():
                if name[-14:] == 'vbaProject.bin':
                    data = zf.read(name)
                    open(tmp_file, 'wb').write(data)
                    return tmp_file
            print os.path.basename(filename) + ': No vbaProject.bin found in zip arachive.'
        except Exception as e:
            print os.path.basename(filename) + ': ' + str(e)

    if data[0x00:0x08] == 'IE1JTUUt':
        m = re.search('IE1JTU[0-9a-zA-Z/+=\x0d\x0a]{1000,}', data)
        if m is not None:
            b64data = m.group(0)
            data = base64.b64decode(b64data)

    if data.find('MIME-Version') != -1:
        m = re.search('QWN0aX[0-9a-zA-Z/+=\x0d\x0a]{1000,}', data)
        if m is not None:
            b64data = m.group(0)
            data = base64.b64decode(b64data)
            try:
                data = zlib.decompress(data[0x32:])
                open(tmp_file, 'wb').write(data)
                return tmp_file
            except Exception as e:
                print filename + ' ' + str(e)

    return None


def read_sigs(filename):
    sig_list = list()

    for line in open(filename, 'rb'):
        sig_list.append(line.strip())

    return sig_list


if __name__ == '__main__':

    init_logging(False)
    
    if len(sys.argv) >= 3 and len(sys.argv) <= 4:
        action = 0
        if len(sys.argv) == 4:
            if sys.argv[3] == '-copy':
                action = 1
            elif sys.argv[3] == '-move':
                action = 2
            else:
                print 'Usage: ' + sys.argv[0] + ' directory signature.txt [-copy/-move]'
                exit(0)
        if os.path.isdir(sys.argv[1]):
            if os.path.isfile(sys.argv[2]):
                sig_list = read_sigs(sys.argv[2])
                parse_files(sys.argv[1], sig_list, action)
            else:
                print 'Invalid file:', sys.argv[2]
        else:
            print 'Invalid directory:', sys.argv[1]
    else:
        print 'Usage: ' + sys.argv[0] + ' directory signature.txt [-copy/-move]'

    
        