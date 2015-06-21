# An OLE file format parser

import os
import struct
import logging


def init_logging(debug):
    ole_logger = logging.getLogger('ole.logger')
    ch = logging.StreamHandler()
            
    if debug:
        ole_logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    else:
        ole_logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
                
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    ole_logger.addHandler(ch)

    if debug:
        ole_logger.debug('In debug mode.')


class OLEHeader:

    ole_logger = None
    
    '''OLE Header'''
    Signature = ''
    CLSID = ''
    MinorVersion = 0
    MajorVersion = 0
    ByteOrder = 0
    SectorShift = 0
    MiniSectorShift = 0
    Reserved = ''
    NumberOfDirectorySectors = 0
    NumberOfFATSectors = 0
    FirstDirecotrySector = 0
    TransactionSignatureNumber = 0
    MiniStreamCutoffSize = 0
    FirstMiniFATSector = 0
    NumberOfMiniFATSectors = 0
    FirstDIFATSector = 0
    NumberOfDIFATSectors = 0
    DIFAT = list()


    def __init__(self, data):
        self.ole_logger = None
        self.Signature = ''
        self.CLSID = ''
        self.MinorVersion = 0
        self.MajorVersion = 0
        self.ByteOrder = 0
        self.SectorShift = 0
        self.MiniSectorShift = 0
        self.Reserved = ''
        self.NumberOfDirectorySectors = 0
        self.NumberOfFATSectors = 0
        self.FirstDirecotrySector = 0
        self.TransactionSignatureNumber = 0
        self.MiniStreamCutoffSize = 0
        self.FirstMiniFATSector = 0
        self.NumberOfMiniFATSectors = 0
        self.FirstDIFATSector = 0
        self.NumberOfDIFATSectors = 0
        self.DIFAT = list()
        
        self.ole_logger = logging.getLogger('ole.logger')
        self.ole_logger.debug('Begin to parse OLE header.')
        
        self.Signature = data[0x00:0x08]
        self.ole_logger.debug('Header.Signature: ' + self.Signature.encode('hex').upper())
        if self.Signature != '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            self.raise_exception('OLEHeader.Signature verify failed.')
        
        self.CLSID = data[0x08:0x18]
        self.ole_logger.debug('Header.CLSID: ' + self.CLSID.encode('hex').upper())
        if self.CLSID != '\x00' * 16:
            self.ole_logger.warning('OLEHeader.CLSID is not null.')

        self.MinorVersion = struct.unpack('<H', data[0x18:0x1A])[0]
        self.ole_logger.debug('Header.MinorVersion: ' + str(hex(self.MinorVersion)))

        self.MajorVersion = struct.unpack('<H', data[0x1A:0x1C])[0]
        self.ole_logger.debug('Header.MajorVersion: ' + str(hex(self.MajorVersion)))
        if self.MajorVersion != 0x03 and self.MajorVersion != 0x04:
            self.raise_exception('OLEHeader.MajorVersion has an abnormal value.')

        self.ByteOrder = struct.unpack('<H', data[0x1C:0x1E])[0]
        if self.ByteOrder == 0xFFFE:
            self.ole_logger.debug('Header.ByteOrder: ' + str(hex(self.ByteOrder)) + ' (little-endian)')
        else:
            self.ole_logger.debug('Header.ByteOrder: ' + str(hex(self.ByteOrder)))
            self.raise_exception('OLEHeader.ByteOrder has an abnormal value.')

        self.SectorShift = struct.unpack('<H', data[0x1E:0x20])[0]
        if self.SectorShift == 0x09:
            self.ole_logger.debug('Header.SectorShift: ' + str(hex(self.SectorShift)) + ' (512 bytes)')
        elif self.SectorShift == 0x0C:
            self.ole_logger.debug('Header.SectorShift: ' + str(hex(self.SectorShift)) + ' (4096 bytes)')
        else:
            self.ole_logger.debug('Header.SectorShift: ' + str(hex(self.SectorShift)))
            self.raise_exception('OLEHeader.SectorShift has an abnormal value.')

        self.MiniSectorShift = struct.unpack('<H', data[0x20:0x22])[0]
        if self.MiniSectorShift == 0x06:
            self.ole_logger.debug('Header.MiniSectorShift: ' + str(hex(self.MiniSectorShift)) + ' (64 bytes)')
        else:
            self.ole_logger.debug('Header.MiniSectorShift: ' + str(hex(self.MiniSectorShift)))
            self.raise_exception('OLEHeader.MiniSectorShift has an abnormal value.')

        self.Reserved = data[0x22:0x28]
        self.ole_logger.debug('Header.Reserved: ' + self.Reserved.encode('hex').upper())
        if self.Reserved != '\x00' * 6:
            self.ole_logger.warning('OLEHeader.Reserved is not all zeros.')

        self.NumberOfDirectorySectors = struct.unpack('<I', data[0x28:0x2C])[0]
        self.ole_logger.debug('Header.NumberOfDirectorySectors: ' + str(hex(self.NumberOfDirectorySectors)))
        if self.NumberOfDirectorySectors != 0x0 and self.MajorVersion != 0x04:
            self.raise_exception('OLEHeader.NumberOfDirectorySectors has an abnormal value.')
        
        self.NumberOfFATSectors = struct.unpack('<I', data[0x2C:0x30])[0]
        self.ole_logger.debug('Header.NumberOfFATSectors: ' + str(hex(self.NumberOfFATSectors)))

        self.FirstDirecotrySector = struct.unpack('<I', data[0x30:0x34])[0]
        self.ole_logger.debug('Header.FirstDirecotrySector: ' + str(hex(self.FirstDirecotrySector)))

        self.TransactionSignatureNumber = struct.unpack('<I', data[0x34:0x38])[0]
        self.ole_logger.debug('Header.TransactionSignatureNumber: ' + str(hex(self.TransactionSignatureNumber)))

        self.MiniStreamCutoffSize = struct.unpack('<I', data[0x38:0x3C])[0]
        self.ole_logger.debug('Header.MiniStreamCutoffSize: ' + str(hex(self.MiniStreamCutoffSize)))
        if self.MiniStreamCutoffSize != 0x1000:
            self.raise_exception('OLEHeader.MiniStreamCutoffSize has an abnormal value.')

        self.FirstMiniFATSector = struct.unpack('<I', data[0x3C:0x40])[0]
        self.ole_logger.debug('Header.FirstMiniFATSector: ' + str(hex(self.FirstMiniFATSector)))

        self.NumberOfMiniFATSectors = struct.unpack('<I', data[0x40:0x44])[0]
        self.ole_logger.debug('Header.NumberOfMiniFATSectors: ' + str(hex(self.NumberOfMiniFATSectors)))

        self.FirstDIFATSector = struct.unpack('<I', data[0x44:0x48])[0]
        self.ole_logger.debug('Header.FirstDIFATSector: ' + str(hex(self.FirstDIFATSector)))

        self.NumberOfDIFATSectors = struct.unpack('<I', data[0x48:0x4C])[0]
        self.ole_logger.debug('Header.NumberOfDIFATSectors: ' + str(hex(self.NumberOfDIFATSectors)))

        if self.NumberOfDIFATSectors > 0 and self.FirstDIFATSector == 0xFFFFFFFE:
            self.raise_exception('OLEHeader.NumberOfDIFATSectors or OLEHeader.FirstDIFATSector has an abnormal value.')
        
        for i in range(0, 109):
            difat = struct.unpack('<I', data[0x4C+i*4:0x4C+i*4+4])[0]
            if difat == 0xFFFFFFFF:
                break
            self.ole_logger.debug('Header.NumberOfDIFATSectors[' + str(i) + '] :' + str(hex(difat)))
            self.DIFAT.append(difat)

        for j in range(i, 109):
            difat = struct.unpack('<I', data[0x4C+j*4:0x4C+j*4+4])[0]
            if difat != 0xFFFFFFFF:
                self.raise_exception('OLEHeader.DIFAT['  + str(j) + '] has an abnormal value.')


    def raise_exception(self, error):
        self.ole_logger.error(error)
        raise Exception(error)


class OLEFile:

    ole_logger = None
    file_data = None
    sector_size = 0

    OLEHeader = None
    DIFAT = list()
    FAT = list()


    def __init__(self, filename):
        self.ole_logger = None
        self.file_data = None
        self.sector_size = 0
        self.OLEHeader = None
        self.DIFAT = list()
        self.FAT = list()
        
        self.ole_logger = logging.getLogger('ole.logger')
        
        if os.path.isfile(filename):
            self.file_data = open(filename, 'rb').read()
            self.ole_logger.debug('Load file: ' + filename)

            self.OLEHeader = OLEHeader(self.file_data)

            if self.OLEHeader.SectorShift == 0x09:
                self.sector_size = 512
            elif self.OLEHeader.SectorShift == 0x0C:
                self.sector_size = 4096
            else:
                self.raise_exception('Invalid SectorSize.')

            self.init_fat_chain()
        else:
            self.raise_exception('Invalid file: ' + filename)


    def init_fat_chain(self):
        self.DIFAT = list(self.OLEHeader.DIFAT)

        if self.OLEHeader.NumberOfDIFATSectors > 0:
            difat_sector_index = self.OLEHeader.FirstDIFATSector
            for i in range(0, self.OLEHeader.NumberOfDIFATSectors):
                difat_sector_offset = (difat_sector_index+1) * self.sector_size
                self.ole_logger.debug('DIFAT sector #' + str(i) + ' at offset: ' + str(hex(difat_sector_offset)))
                for j in range(0, self.sector_size/4-1):
                    difat = struct.unpack('<I', self.file_data[difat_sector_offset+j*4:difat_sector_offset+j*4+4])[0]
                    if difat == 0xFFFFFFFF:
                        if i+1 == self.OLEHeader.NumberOfDIFATSectors:
                            break
                        else:
                            raise_exception('Encounter an invalid DIFAT value when parsing DIFAT chain.')
                    self.ole_logger.debug('DIFT[' + str(len(self.DIFAT)) + '] :' + str(hex(difat)))
                    self.DIFAT.append(difat)    
                difat_sector_index = struct.unpack('<I', self.file_data[difat_sector_offset+j*4:difat_sector_offset+j*4+4])[0]
                    
        if len(self.DIFAT) != self.OLEHeader.NumberOfFATSectors:
            raise_exception('OLEHeader.NumberOfFATSectors do not mahtch the number of the DIFAT entries.')

        fat_sector_index = self.OLEHeader.DIFAT[0]   
        for i in range(0, self.OLEHeader.NumberOfFATSectors):
            fat_sector_offset = (fat_sector_index+1) * self.sector_size
            self.ole_logger.debug('FAT sector #' + str(i) + ' at offset: ' + str(hex(fat_sector_offset)))
            for j in range(0, self.sector_size/4):
                fat = struct.unpack('<I', self.file_data[fat_sector_offset+j*4:fat_sector_offset+j*4+4])[0]
                self.FAT.append(fat)
                if fat == 0xFFFFFFFC:
                    self.ole_logger.debug('FAT[' + str(len(self.FAT)-1) + '] is a DIFAT sector')
                if fat == 0xFFFFFFFD:
                    self.ole_logger.debug('FAT[' + str(len(self.FAT)-1) + '] is a FAT sector')

    
    def raise_exception(self, error):
        self.ole_logger.error(error)
        raise Exception(error)


def test_ole():
    try:
        olefile = OLEFile('oletest.doc')
    except Exception as e:
        print e
        

if __name__ == '__main__':
    
    debug = True
    #debug = False
    init_logging(debug)
    
    test_ole()
