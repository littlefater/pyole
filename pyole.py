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
            self._raise_exception('OLEHeader.Signature verify failed.')
        
        self.CLSID = data[0x08:0x18]
        self.ole_logger.debug('Header.CLSID: ' + self.CLSID.encode('hex').upper())
        if self.CLSID != '\x00' * 16:
            self.ole_logger.warning('OLEHeader.CLSID is not null.')

        self.MinorVersion = struct.unpack('<H', data[0x18:0x1A])[0]
        self.ole_logger.debug('Header.MinorVersion: ' + str(hex(self.MinorVersion)))

        self.MajorVersion = struct.unpack('<H', data[0x1A:0x1C])[0]
        self.ole_logger.debug('Header.MajorVersion: ' + str(hex(self.MajorVersion)))
        if self.MajorVersion != 0x03 and self.MajorVersion != 0x04:
            self._raise_exception('OLEHeader.MajorVersion has an abnormal value.')

        self.ByteOrder = struct.unpack('<H', data[0x1C:0x1E])[0]
        if self.ByteOrder == 0xFFFE:
            self.ole_logger.debug('Header.ByteOrder: ' + str(hex(self.ByteOrder)) + ' (little-endian)')
        else:
            self.ole_logger.debug('Header.ByteOrder: ' + str(hex(self.ByteOrder)))
            self._raise_exception('OLEHeader.ByteOrder has an abnormal value.')

        self.SectorShift = struct.unpack('<H', data[0x1E:0x20])[0]
        if self.SectorShift == 0x09:
            self.ole_logger.debug('Header.SectorShift: ' + str(hex(self.SectorShift)) + ' (512 bytes)')
        elif self.SectorShift == 0x0C:
            self.ole_logger.debug('Header.SectorShift: ' + str(hex(self.SectorShift)) + ' (4096 bytes)')
        else:
            self.ole_logger.debug('Header.SectorShift: ' + str(hex(self.SectorShift)))
            self._raise_exception('OLEHeader.SectorShift has an abnormal value.')

        self.MiniSectorShift = struct.unpack('<H', data[0x20:0x22])[0]
        if self.MiniSectorShift == 0x06:
            self.ole_logger.debug('Header.MiniSectorShift: ' + str(hex(self.MiniSectorShift)) + ' (64 bytes)')
        else:
            self.ole_logger.debug('Header.MiniSectorShift: ' + str(hex(self.MiniSectorShift)))
            self._raise_exception('OLEHeader.MiniSectorShift has an abnormal value.')

        self.Reserved = data[0x22:0x28]
        self.ole_logger.debug('Header.Reserved: ' + self.Reserved.encode('hex').upper())
        if self.Reserved != '\x00' * 6:
            self.ole_logger.warning('OLEHeader.Reserved is not all zeros.')

        self.NumberOfDirectorySectors = struct.unpack('<I', data[0x28:0x2C])[0]
        self.ole_logger.debug('Header.NumberOfDirectorySectors: ' + str(hex(self.NumberOfDirectorySectors)))
        if self.NumberOfDirectorySectors != 0x0 and self.MajorVersion != 0x04:
            self._raise_exception('OLEHeader.NumberOfDirectorySectors has an abnormal value.')
        
        self.NumberOfFATSectors = struct.unpack('<I', data[0x2C:0x30])[0]
        self.ole_logger.debug('Header.NumberOfFATSectors: ' + str(hex(self.NumberOfFATSectors)))

        self.FirstDirecotrySector = struct.unpack('<I', data[0x30:0x34])[0]
        self.ole_logger.debug('Header.FirstDirecotrySector: ' + str(hex(self.FirstDirecotrySector)))
        if self.FirstDirecotrySector == 0:
            self._raise_exception('OLEHeader.FirstDirecotrySector is zero.')

        self.TransactionSignatureNumber = struct.unpack('<I', data[0x34:0x38])[0]
        self.ole_logger.debug('Header.TransactionSignatureNumber: ' + str(hex(self.TransactionSignatureNumber)))

        self.MiniStreamCutoffSize = struct.unpack('<I', data[0x38:0x3C])[0]
        self.ole_logger.debug('Header.MiniStreamCutoffSize: ' + str(hex(self.MiniStreamCutoffSize)))
        if self.MiniStreamCutoffSize != 0x1000:
            self._raise_exception('OLEHeader.MiniStreamCutoffSize has an abnormal value.')

        self.FirstMiniFATSector = struct.unpack('<I', data[0x3C:0x40])[0]
        self.ole_logger.debug('Header.FirstMiniFATSector: ' + str(hex(self.FirstMiniFATSector)))

        self.NumberOfMiniFATSectors = struct.unpack('<I', data[0x40:0x44])[0]
        self.ole_logger.debug('Header.NumberOfMiniFATSectors: ' + str(hex(self.NumberOfMiniFATSectors)))

        if self.NumberOfMiniFATSectors > 0 and self.FirstMiniFATSector == 0xFFFFFFFE:
            self._raise_exception('OLEHeader.NumberOfMiniFATSectors or OLEHeader.FirstMiniFATSector has an abnormal value.')

        self.FirstDIFATSector = struct.unpack('<I', data[0x44:0x48])[0]
        self.ole_logger.debug('Header.FirstDIFATSector: ' + str(hex(self.FirstDIFATSector)))

        self.NumberOfDIFATSectors = struct.unpack('<I', data[0x48:0x4C])[0]
        self.ole_logger.debug('Header.NumberOfDIFATSectors: ' + str(hex(self.NumberOfDIFATSectors)))

        if self.NumberOfDIFATSectors > 0 and self.FirstDIFATSector == 0xFFFFFFFE:
            self._raise_exception('OLEHeader.NumberOfDIFATSectors or OLEHeader.FirstDIFATSector has an abnormal value.')
        
        for i in range(0, 109):
            difat = struct.unpack('<I', data[0x4C+i*4:0x4C+i*4+4])[0]
            if difat == 0xFFFFFFFF:
                break
            self.ole_logger.debug('Header.NumberOfDIFATSectors[' + str(i) + '] :' + str(hex(difat)))
            self.DIFAT.append(difat)

        for j in range(i, 109):
            difat = struct.unpack('<I', data[0x4C+j*4:0x4C+j*4+4])[0]
            if difat != 0xFFFFFFFF:
                self._raise_exception('OLEHeader.DIFAT['  + str(j) + '] has an abnormal value.')


    def _raise_exception(self, error):
        self.ole_logger.error(error)
        raise Exception(error)


class Directory:

    ole_logger = None

    Name = ''
    NameLength = 0
    ObjectType = 0
    ColorFlag = 0
    LeftSiblingID = 0
    RightSiblingID = 0
    ChildID = 0
    CLSID = ''
    StateBits = 0
    CreationTime = ''
    ModifiedTime = ''
    StartingSector = 0
    StreamSize = 0

    def __init__(self, data):
        self.ole_logger = None
        self.Name = ''
        self.NameLength = 0
        self.ObjectType = 0
        self.ColorFlag = 0
        self.LeftSiblingID = 0
        self.RightSiblingID = 0
        self.ChildID = 0
        self.CLSID = ''
        self.StateBits = 0
        self.CreationTime = ''
        self.ModifiedTime = ''
        self.StartingSector = 0
        self.StreamSize = 0

        self.ole_logger = logging.getLogger('ole.logger')

        self.Name = data[0:0x40].decode('utf-16').strip('\x00')
        self.ole_logger.debug('Dir.Name: ' + self.Name)

        self.NameLength = struct.unpack('<H', data[0x40:0x42])[0]
        self.ole_logger.debug('Dir.NameLength: ' + str(self.NameLength))
        
        if self.NameLength != len(self.Name)*2+2:
            self._raise_exception('DirectoryEntry.NameLength has a wrong value.')
        
        self.ObjectType = ord(data[0x42])
        if self.ObjectType == 0x00:  
            self.ole_logger.debug('Dir.ObjectType: ' + str(self.ObjectType) + ' (unallocated)')
        elif self.ObjectType == 0x01:
            self.ole_logger.debug('Dir.ObjectType: ' + str(self.ObjectType) + ' (storage object)')
        elif self.ObjectType == 0x02:
            self.ole_logger.debug('Dir.ObjectType: ' + str(self.ObjectType) + ' (stream object)')
        elif self.ObjectType == 0x05:
            self.ole_logger.debug('Dir.ObjectType: ' + str(self.ObjectType) + ' (root storage object)')
        else:
            self._raise_exception('DirectoryEntry.ObjectType has an abnormal value.')

        self.ColorFlag = ord(data[0x43])
        if self.ColorFlag == 0x00:  
            self.ole_logger.debug('Dir.ColorFlag: ' + str(self.ColorFlag) + ' (red)')
        elif self.ColorFlag == 0x01:
            self.ole_logger.debug('Dir.ColorFlag: ' + str(self.ColorFlag) + ' (black)')
        else:
            self._raise_exception('DirectoryEntry.ColorFlag has an abnormal value.')

        self.LeftSiblingID = struct.unpack('<I', data[0x44:0x48])[0]
        if self.LeftSiblingID >= 0 and self.LeftSiblingID <= 0xFFFFFFF9:
            self.ole_logger.debug('Dir.LeftSiblingID: ' + str(hex(self.LeftSiblingID)) + ' (REGSID)')
        elif self.LeftSiblingID == 0xFFFFFFFF:
            self.ole_logger.debug('Dir.LeftSiblingID: ' + str(hex(self.LeftSiblingID)) + ' (NOSTREAM)')
        else:
            self._raise_exception('DirectoryEntry.LeftSiblingID has an abnormal value.')

        self.RightSiblingID = struct.unpack('<I', data[0x48:0x4C])[0]
        if self.RightSiblingID >= 0 and self.RightSiblingID <= 0xFFFFFFF9:
            self.ole_logger.debug('Dir.RightSiblingID: ' + str(hex(self.RightSiblingID)) + ' (REGSID)')
        elif self.RightSiblingID == 0xFFFFFFFF:
            self.ole_logger.debug('Dir.LeftSiblingID: ' + str(hex(self.RightSiblingID)) + ' (NOSTREAM)')
        else:
            self._raise_exception('DirectoryEntry.RightSiblingID has an abnormal value.')

        self.ChildID = struct.unpack('<I', data[0x4C:0x50])[0]
        if self.ChildID >= 0 and self.ChildID <= 0xFFFFFFF9:
            self.ole_logger.debug('Dir.ChildID: ' + str(hex(self.ChildID)) + ' (REGSID)')
        elif self.ChildID == 0xFFFFFFFF:
            self.ole_logger.debug('Dir.ChildID: ' + str(hex(self.ChildID)) + ' (NOSTREAM)')
        else:
            self._raise_exception('DirectoryEntry.ChildID has an abnormal value.')

        self.CLSID = data[0x50:0x60]
        self.ole_logger.debug('Dir.CLSID: ' + self.CLSID.encode('hex'))

        self.StateBits = struct.unpack('<I', data[0x60:0x64])[0]
        self.ole_logger.debug('Dir.StateBits: ' + str(hex(self.StateBits)))

        self.CreationTime = data[0x64:0x6C]
        self.ole_logger.debug('Dir.CreationTime: ' + self.CreationTime.encode('hex'))

        self.ModifiedTime = data[0x6C:0x74]
        self.ole_logger.debug('Dir.ModifiedTime: ' + self.ModifiedTime.encode('hex'))

        self.StartingSector = struct.unpack('<I', data[0x74:0x78])[0]
        self.ole_logger.debug('Dir.StartingSector: ' + str(hex(self.StartingSector)))

        self.StreamSize = struct.unpack('<Q', data[0x78:0x80])[0]
        self.ole_logger.debug('Dir.StreamSize: ' + str(hex(self.StreamSize)))
        
        
    def _raise_exception(self, error):
        self.ole_logger.error(error)
        raise Exception(error)


class OLEFile:

    ole_logger = None
    file_data = None
    sector_size = 0

    OLEHeader = None
    DIFAT = list()
    FAT = list()
    MiniFAT = list()
    Directory = list()


    def __init__(self, filename):
        self.ole_logger = None
        self.file_data = None
        self.sector_size = 0
        self.OLEHeader = None
        self.DIFAT = list()
        self.FAT = list()
        self.MiniFAT = list()
        self.Directory = list()
        
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
                self._raise_exception('Invalid SectorSize.')

            self._init_fat_chain()

            if self.OLEHeader.NumberOfMiniFATSectors > 0:
                self._init_minifat_chain()

            self._init_dir_entry()
        else:
            self._raise_exception('Invalid file: ' + filename)


    def _init_fat_chain(self):
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
                            _raise_exception('Encounter an invalid DIFAT value when parsing DIFAT chain.')
                    self.ole_logger.debug('DIFT[' + str(len(self.DIFAT)) + ']: ' + str(hex(difat)))
                    self.DIFAT.append(difat)    
                difat_sector_index = struct.unpack('<I', self.file_data[difat_sector_offset+j*4:difat_sector_offset+j*4+4])[0]
                    
        if len(self.DIFAT) != self.OLEHeader.NumberOfFATSectors:
            self._raise_exception('OLEHeader.NumberOfFATSectors does not mahtch the number of the DIFAT entries.')
           
        for i in range(0, self.OLEHeader.NumberOfFATSectors):
            fat_sector_index = self.OLEHeader.DIFAT[i]
            fat_sector_offset = (fat_sector_index+1) * self.sector_size
            self.ole_logger.debug('FAT sector #' + str(i) + ' at offset: ' + str(hex(fat_sector_offset)))
            for j in range(0, self.sector_size/4):
                fat = struct.unpack('<I', self.file_data[fat_sector_offset+j*4:fat_sector_offset+j*4+4])[0]
                self.FAT.append(fat)
                if fat == 0xFFFFFFFC:
                    self.ole_logger.debug('FAT[' + str(len(self.FAT)-1) + '] is a DIFAT sector')
                if fat == 0xFFFFFFFD:
                    self.ole_logger.debug('FAT[' + str(len(self.FAT)-1) + '] is a FAT sector')

    
    def _init_minifat_chain(self):
        minifat_sector_index = self.OLEHeader.FirstMiniFATSector
        for i in range(0, self.OLEHeader.NumberOfMiniFATSectors):
            minifat_sector_offset = (minifat_sector_index+1) * self.sector_size
            for j in range(0, self.sector_size/4):
                minifat = struct.unpack('<I', self.file_data[minifat_sector_offset+j*4:minifat_sector_offset+j*4+4])[0]
                self.MiniFAT.append(minifat)
            minifat_sector_index = self.FAT[minifat_sector_index]
            if minifat_sector_index == 0xFFFFFFFE and (i+1) != self.OLEHeader.NumberOfMiniFATSectors:
                self._raise_exception('self.OLEHeader.NumberOfMiniFATSectors does not match the length of the MiniFat sector chian.')
    

    def _init_dir_entry(self):
        dir_sector_index = self.OLEHeader.FirstDirecotrySector
        is_end = False
        while True:
            dir_sector_offset = (dir_sector_index+1) * self.sector_size
            for i in range(0, self.sector_size/128):
                dir_data = self.file_data[dir_sector_offset+i*128:dir_sector_offset+i*128+128]
                if struct.unpack('<H', dir_data[0x40:0x42])[0] == 0:
                    is_end = True
                    break
                self.ole_logger.debug('###### Directory #' + str(len(self.Directory)) + ' ######')
                directory = Directory(dir_data)    
                self.Directory.append(directory)
            dir_sector_index = self.FAT[dir_sector_index]
            if is_end or dir_sector_index == 0xFFFFFFFE:
                break

    
    def _raise_exception(self, error):
        self.ole_logger.error(error)
        raise Exception(error)


    def find_object_by_name(self, name):
        data = ''
        dir_number = len(self.Directory)
        
        for i in range(0, dir_number):
            directory = self.Directory[i]
            if name == directory.Name:
                sector_index = directory.StartingSector
                if sector_index == 0xFFFFFFFE:
                    self._raise_exception('Object: ' + name + ' has no data.')
                
                while sector_index != 0xFFFFFFFE:
                    sector_offset = (sector_index+1) * self.sector_size
                    data += self.file_data[sector_offset:sector_offset+self.sector_size]
                    sector_index = self.FAT[sector_index]
                
                break
        
        if (i+1) == dir_number:
            self._raise_exception('Could not find object: ' + name)

        if directory.StreamSize > len(data):
            self._raise_exception('DirectoryEntry.StreamSize larger than real data size.')
            
        return data[0: directory.StreamSize]

    
    def find_object_by_index(self, index):
        data = ''
        
        if index < 0 or index >= len(self.Directory):
            self._raise_exception('Index out of boundary.')
            
        directory = self.Directory[index]
        sector_index = directory.StartingSector
        if sector_index == 0xFFFFFFFE:
            self._raise_exception('Object #' + str(index) + ' has no data.')

        while sector_index != 0xFFFFFFFE:
            sector_offset = (sector_index+1) * self.sector_size
            data += self.file_data[sector_offset:sector_offset+self.sector_size]
            sector_index = self.FAT[sector_index]

        if directory.StreamSize > len(data):
            self._raise_exception('DirectoryEntry.StreamSize larger than real data size.')
            
        return data[0: directory.StreamSize]


init_logging(False)


if __name__ == '__main__':
    debug = True
    init_logging(debug)

    

   
    
    

