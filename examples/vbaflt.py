#!/usr/bin/env python
"""
pyvba example: filter out samples based on strings in VBA

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
import argparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pyvba import *


def check_vba(filename, siglist, no_order):
    
    try:
        vbafile = VBAFile(filename)

        vba_code = ''
        for ModuleRecord in vbafile.dir.ModulesRecord.ModuleArray:
            codepage = 'cp' + str(vbafile.dir.InformationRecord.CodePageRecord.CodePage)
            if codepage == 'cp10000':
                code = vbafile.OLE.find_object_by_name(ModuleRecord.NameRecord.ModuleName.decode('mac_roman'))[ModuleRecord.OffsetRecord.TextOffset:]
            else:
                code = vbafile.OLE.find_object_by_name(ModuleRecord.NameRecord.ModuleName.decode(codepage))[ModuleRecord.OffsetRecord.TextOffset:]
            vba_code += vbafile._decompress(code)

        if no_order:
            for sig in siglist:
                if -1 == vba_code.find(sig):
                    return -1
        else:
            index = 0
            for sig in siglist:
                index1 = vba_code[index:].find(sig)
                if -1 == index1:
                    return -1
                index = index + index1 + 1

        return 1
            
    except Exception as e:
        print os.path.basename(filename) + ': ' + str(e)
        return -2


def parse_files(filedir, siglist, action, no_order, move_unsupport):

    if action:
        out_dir = 'flt_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
        os.makedirs(out_dir)

    count = 0
    unsupport_dir = ''
    for root, dirs, files in os.walk(filedir):
        for file in files:
            filename = os.path.join(root, file)

            ole_file = extract_ole_file(filename)
            if ole_file is not None:
                result = check_vba(ole_file, siglist, no_order)
                
                if ole_file[0x00:0x07] == 'tmpole_':
                    os.remove(ole_file)
                if 1 == result:
                    count += 1
                    print file
                    if 1 == action:
                        newfile = os.path.join(out_dir, file)
                        shutil.copy2(filename, newfile)
                    elif 2 == action:
                        newfile = os.path.join(out_dir, file)
                        shutil.move(filename, newfile)
                elif -2 == result:
                    print file + ': Unable to parse file.'
                    if move_unsupport:
                        if unsupport_dir == '':
                            unsupport_dir = 'unsupport_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
                            os.makedirs(unsupport_dir)
                        newfile = os.path.join(unsupport_dir, file)
                        shutil.move(filename, newfile)
                        print 'Unsupported file moved to: ' + newfile
            else: 
                print file + ': Unsupported file.'
                if move_unsupport:
                    if unsupport_dir == '':
                        unsupport_dir = 'unsupport_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
                        os.makedirs(unsupport_dir)
                    newfile = os.path.join(unsupport_dir, file)
                    shutil.move(filename, newfile)
                    print 'Unsupported file moved to: ' + newfile
    
    if count > 0:
        print 'Found ' + str(count) + ' files.'
    else:
        print 'No file found, please adjust your signatures.'

    if action and count:
        if 1 == action:
            print 'Files copied to: ' + out_dir
        elif 2 == action:
            print 'Files moved to: ' + out_dir
    elif action:
        os.removedirs(out_dir)


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
        m = re.search('Q[\x0d\x0a]*W[\x0d\x0a]*N[\x0d\x0a]*0[\x0d\x0a]*a[\x0d\x0a]*X[0-9a-zA-Z/+=\x0d\x0a\x20]{1000,}', data)
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

    parser = argparse.ArgumentParser(description='Filter out samples based on strings in VBA')
    parser.add_argument('directory', action='store', help='path to the sample directory')
    parser.add_argument('sigfile', action='store', help='path to signature file')
    parser.add_argument('-no', '--no-order', action='store_true', help='ignore the signature order')
    parser.add_argument('-mu', '--move-unsupport', action='store_true', help='move unsupported files to a separate folder')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', '--copy', action='store_true', help='copy matched files to a separate folder')
    group.add_argument('-m', '--move', action='store_true', help='move matched files to a separate folder')

    args = parser.parse_args()
    action = 0
    
    if False == os.path.isdir(args.directory):
        print 'Invalid directory:', args.directory
        exit(0)
    
    if False == os.path.isfile(args.sigfile):
        print 'Invalid signature file:', args.sigfile
        exit(0)
    
    siglist = read_sigs(sys.argv[2])
    if not siglist:
        print 'Can not find valid signatures from file:', args.sigfile
        exit(0)
    
    if args.copy:
        action = 1
    elif args.move:
        action = 2
    
    parse_files(args.directory, siglist, action, args.no_order, args.move_unsupport)

        