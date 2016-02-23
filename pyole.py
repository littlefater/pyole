# An OLE file format parser

import os
import struct
import logging
import datetime


PIDSI = {'PIDSI_CODEPAGE':0x01, 'PIDSI_TITLE':0x02, 'PIDSI_SUBJECT':0x03, 'PIDSI_AUTHOR':0x04, 'PIDSI_KEYWORDS':0x05,
        'PIDSI_COMMENTS':0x06, 'PIDSI_TEMPLATE':0x07, 'PIDSI_LASTAUTHOR':0x08, 'PIDSI_REVNUMBER':0x09, 'PIDSI_EDITTIME':0x0A,
        'PIDSI_LASTPRINTED':0x0B, 'PIDSI_CREATE_DTM':0x0C, 'PIDSI_LASTSAVE_DTM':0x0D, 'PIDSI_PAGECOUNT':0x0E, 'PIDSI_WORDCOUNT':0x0F,
        'PIDSI_CHARCOUNT':0x10, 'PIDSI_APPNAME':0x12, 'PIDSI_DOC_SECURITY':0x13}

PIDDSI = {'GKPIDDSI_CODEPAGE':0x01, 'GKPIDDSI_CATEGORY':0x02, 'GKPIDDSI_PRESFORMAT':0x03, 'GKPIDDSI_BYTECOUNT':0x04, 'GKPIDDSI_LINECOUNT':0x05,
        'GKPIDDSI_PARACOUNT':0x06, 'GKPIDDSI_SLIDECOUNT':0x07, 'GKPIDDSI_NOTECOUNT':0x08, 'GKPIDDSI_HIDDENCOUNT':0x09, 'GKPIDDSI_MMCLIPCOUNT':0x0A,
        'GKPIDDSI_SCALE':0x0B, 'GKPIDDSI_HEADINGPAIR':0x0C, 'GKPIDDSI_DOCPARTS':0x0D, 'GKPIDDSI_MANAGER':0x0E, 'GKPIDDSI_COMPANY':0x0F,
        'GKPIDDSI_LINKSDIRTY':0x10, 'GKPIDDSI_CCHWITHSPACES':0x11, 'GKPIDDSI_SHAREDDOC':0x13, 'GKPIDDSI_LINKBASE':0x14, 'GKPIDDSI_HLINKS':0x15,
        'GKPIDDSI_HYPERLINKSCHANGED':0x16, 'GKPIDDSI_VERSION':0x17, 'GKPIDDSI_DIGSIG':0x18, 'GKPIDDSI_CONTENTTYPE':0x1A, 'GKPIDDSI_CONTENTSTATUS':0x1B,
        'GKPIDDSI_LANGUAGE':0x1C, 'GKPIDDSI_DOCVERSION':0x1D}

PropertyType= {'VT_EMPTY':0x00, 'VT_NULL':0x01, 'VT_I2':0x02, 'VT_I4':0x03, 'VT_R4':0x04, 'VT_R8':0x05, 'VT_CY':0x06, 'VT_DATE': 0x07, 'VT_BSTR':0x08,
        'VT_ERROR':0x0A, 'VT_BOOL':0x0B, 'VT_VARIANT':0x0C, 'VT_DECIMAL':0x0E, 'VT_I1':0x10, 'VT_UI1':0x11, 'VT_UI2':0x12, 'VT_UI4':0x13, 'VT_I8':0x14, 'VT_UI8':0x15,
        'VT_INT':0x16, 'VT_UINT':0x17, 'VT_LPSTR':0x1E, 'VT_LPWSTR':0x1F, 'VT_FILETIME':0x40, 'VT_BLOB':0x41, 'VT_STREAM':0x42, 'VT_STORAGE':0x43,
        'VT_STREAMED_Object':0x44, 'VT_STORED_Object':0x45, 'VT_BLOB_Object':0x46, 'VT_CF':0x47, 'VT_CLSID':0x48, 'VT_VERSIONED_STREAM':0x49,
        'VT_VECTOR':0x1000, 'VT_ARRAY':0x2000}


def init_logging(debug):
    ole_logger = logging.getLogger('ole.logger')
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            
    if debug:
        ole_logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        fh = logging.FileHandler('debug.log')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        ole_logger.addHandler(fh)
    else:
        ole_logger.setLevel(logging.ERROR)
        ch.setLevel(logging.ERROR)         
    
    ch.setFormatter(formatter)
    ole_logger.addHandler(ch)

    if debug:
        ole_logger.debug('In debug mode.')


class OLEBase:
    
    ole_logger = logging.getLogger('ole.logger')

    def __init__(self):
        pass

    def _raise_exception(self, error):
        #self.ole_logger.error(error)
        self.ole_logger.warning(error)
        raise Exception(error)

    def _filetime_to_datetime(self, microseconds):
        seconds, microseconds = divmod(microseconds/10, 1000000)
        days, seconds = divmod(seconds, 86400)
        date_time = datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(days, seconds, microseconds)
        return str(date_time)


class OLEHeader(OLEBase):

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
        
        self.Signature = data[0x00:0x08]
        self.ole_logger.debug('OLEHeader.Signature: ' + self.Signature.encode('hex').upper())
        if self.Signature != '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            self._raise_exception('OLEHeader.Signature verify failed.')
        
        self.CLSID = data[0x08:0x18]
        self.ole_logger.debug('OLEHeader.CLSID: ' + self.CLSID.encode('hex').upper())
        if self.CLSID != '\x00' * 16:
            self.ole_logger.warning('OLEHeader.CLSID is not null.')

        self.MinorVersion = struct.unpack('<H', data[0x18:0x1A])[0]
        self.ole_logger.debug('OLEHeader.MinorVersion: ' + str(hex(self.MinorVersion)))

        self.MajorVersion = struct.unpack('<H', data[0x1A:0x1C])[0]
        self.ole_logger.debug('OLEHeader.MajorVersion: ' + str(hex(self.MajorVersion)))
        if self.MajorVersion != 0x03 and self.MajorVersion != 0x04:
            self._raise_exception('OLEHeader.MajorVersion has an abnormal value.')

        self.ByteOrder = struct.unpack('<H', data[0x1C:0x1E])[0]
        if self.ByteOrder == 0xFFFE:
            self.ole_logger.debug('OLEHeader.ByteOrder: ' + str(hex(self.ByteOrder)) + ' (little-endian)')
        else:
            self.ole_logger.debug('OLEHeader.ByteOrder: ' + str(hex(self.ByteOrder)))
            self._raise_exception('OLEHeader.ByteOrder has an abnormal value.')

        self.SectorShift = struct.unpack('<H', data[0x1E:0x20])[0]
        if self.SectorShift == 0x09:
            self.ole_logger.debug('OLEHeader.SectorShift: ' + str(hex(self.SectorShift)) + ' (512 bytes)')
        elif self.SectorShift == 0x0C:
            self.ole_logger.debug('OLEHeader.SectorShift: ' + str(hex(self.SectorShift)) + ' (4096 bytes)')
        else:
            self.ole_logger.debug('OLEHeader.SectorShift: ' + str(hex(self.SectorShift)))
            self._raise_exception('OLEHeader.SectorShift has an abnormal value.')

        self.MiniSectorShift = struct.unpack('<H', data[0x20:0x22])[0]
        if self.MiniSectorShift == 0x06:
            self.ole_logger.debug('OLEHeader.MiniSectorShift: ' + str(hex(self.MiniSectorShift)) + ' (64 bytes)')
        else:
            self.ole_logger.debug('OLEHeader.MiniSectorShift: ' + str(hex(self.MiniSectorShift)))
            self._raise_exception('OLEHeader.MiniSectorShift has an abnormal value.')

        self.Reserved = data[0x22:0x28]
        self.ole_logger.debug('OLEHeader.Reserved: ' + self.Reserved.encode('hex').upper())
        if self.Reserved != '\x00' * 6:
            self.ole_logger.warning('OLEHeader.Reserved is not all zeros.')

        self.NumberOfDirectorySectors = struct.unpack('<I', data[0x28:0x2C])[0]
        self.ole_logger.debug('OLEHeader.NumberOfDirectorySectors: ' + str(hex(self.NumberOfDirectorySectors)))
        if self.NumberOfDirectorySectors != 0x0 and self.MajorVersion != 0x04:
            self._raise_exception('OLEHeader.NumberOfDirectorySectors has an abnormal value.')
        
        self.NumberOfFATSectors = struct.unpack('<I', data[0x2C:0x30])[0]
        self.ole_logger.debug('OLEHeader.NumberOfFATSectors: ' + str(hex(self.NumberOfFATSectors)))

        self.FirstDirecotrySector = struct.unpack('<I', data[0x30:0x34])[0]
        self.ole_logger.debug('OLEHeader.FirstDirecotrySector: ' + str(hex(self.FirstDirecotrySector)))
        if self.FirstDirecotrySector == 0:
            self._raise_exception('OLEHeader.FirstDirecotrySector is zero.')

        self.TransactionSignatureNumber = struct.unpack('<I', data[0x34:0x38])[0]
        self.ole_logger.debug('OLEHeader.TransactionSignatureNumber: ' + str(hex(self.TransactionSignatureNumber)))

        self.MiniStreamCutoffSize = struct.unpack('<I', data[0x38:0x3C])[0]
        self.ole_logger.debug('OLEHeader.MiniStreamCutoffSize: ' + str(hex(self.MiniStreamCutoffSize)))
        if self.MiniStreamCutoffSize != 0x1000:
            self._raise_exception('OLEHeader.MiniStreamCutoffSize has an abnormal value.')

        self.FirstMiniFATSector = struct.unpack('<I', data[0x3C:0x40])[0]
        self.ole_logger.debug('OLEHeader.FirstMiniFATSector: ' + str(hex(self.FirstMiniFATSector)))

        self.NumberOfMiniFATSectors = struct.unpack('<I', data[0x40:0x44])[0]
        self.ole_logger.debug('OLEHeader.NumberOfMiniFATSectors: ' + str(hex(self.NumberOfMiniFATSectors)))

        if self.NumberOfMiniFATSectors > 0 and self.FirstMiniFATSector == 0xFFFFFFFE:
            self._raise_exception('OLEHeader.NumberOfMiniFATSectors or OLEHeader.FirstMiniFATSector has an abnormal value.')

        self.FirstDIFATSector = struct.unpack('<I', data[0x44:0x48])[0]
        self.ole_logger.debug('OLEHeader.FirstDIFATSector: ' + str(hex(self.FirstDIFATSector)))

        self.NumberOfDIFATSectors = struct.unpack('<I', data[0x48:0x4C])[0]
        self.ole_logger.debug('OLEHeader.NumberOfDIFATSectors: ' + str(hex(self.NumberOfDIFATSectors)))

        if self.NumberOfDIFATSectors > 0 and self.FirstDIFATSector == 0xFFFFFFFE:
            self._raise_exception('OLEHeader.NumberOfDIFATSectors or OLEHeader.FirstDIFATSector has an abnormal value.')
        
        for i in range(0, 109):
            difat = struct.unpack('<I', data[0x4C+i*4:0x4C+i*4+4])[0]
            if difat == 0xFFFFFFFF:
                break
            self.ole_logger.debug('OLEHeader.DIFAT[' + str(i) + '] :' + str(hex(difat)))
            self.DIFAT.append(difat)

        i += 1
        for j in range(i, 109):
            difat = struct.unpack('<I', data[0x4C+j*4:0x4C+j*4+4])[0]
            if difat != 0xFFFFFFFF:
                self._raise_exception('OLEHeader.DIFAT['  + str(j) + '] has an abnormal value.')


class Directory(OLEBase):

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

        self.CreationTime = struct.unpack('<Q', data[0x64:0x6C])[0]
        self.ole_logger.debug('Dir.CreationTime: ' + self._filetime_to_datetime(self.CreationTime))

        self.ModifiedTime = struct.unpack('<Q', data[0x6C:0x74])[0]
        self.ole_logger.debug('Dir.ModifiedTime: ' + self._filetime_to_datetime(self.ModifiedTime))

        self.StartingSector = struct.unpack('<I', data[0x74:0x78])[0]
        self.ole_logger.debug('Dir.StartingSector: ' + str(hex(self.StartingSector)))

        self.StreamSize = struct.unpack('<Q', data[0x78:0x80])[0]
        self.ole_logger.debug('Dir.StreamSize: ' + str(hex(self.StreamSize)))


class PropertyIdentifierAndOffset(OLEBase):

    PropertyIdentifier = 0
    Offset = 0

    def __init__(self, data):

        self.PropertyIdentifier = 0
        self.Offset = 0

        self.PropertyIdentifier = struct.unpack('<I', data[0:4])[0]
        self.ole_logger.debug('PropertyIdentifierAndOffset.PropertyIdentifier: ' + str(hex(self.PropertyIdentifier)))

        self.Offset = struct.unpack('<I', data[4:8])[0]
        self.ole_logger.debug('PropertyIdentifierAndOffset.Offset: ' + str(hex(self.Offset)))


class DocSummaryInfoPropertySet(OLEBase):

    Size = 0
    NumProperties = 0
    PropertyIdentifierAndOffset = list()
    Property = list()

    def __init__(self, data):
        
        self.Size = 0
        self.NumProperties = 0
        self.PropertyIdentifierAndOffset = list()
        self.Property = list()

        self.Size = struct.unpack('<I', data[0x00:0x04])[0]
        self.ole_logger.debug('DocSummaryInfoPropertySet.Size: ' + str(hex(self.Size)))

        self.NumProperties = struct.unpack('<I', data[0x04:0x08])[0]
        self.ole_logger.debug('DocSummaryInfoPropertySet.NumProperties: ' + str(hex(self.NumProperties)))

        for i in range(0, self.NumProperties):
            piao = PropertyIdentifierAndOffset(data[0x08+i*8:0x08+i*8+8])
            self.PropertyIdentifierAndOffset.append(piao)

        for i in range(0, self.NumProperties):
            if (i+1) < self.NumProperties:
                if self.PropertyIdentifierAndOffset[i].Offset < self.PropertyIdentifierAndOffset[i+1].Offset:
                    property = data[self.PropertyIdentifierAndOffset[i].Offset:self.PropertyIdentifierAndOffset[i+1].Offset]
                else:
                    self.ole_logger.warning('DocSummaryInfoPropertySet.PropertyIdentifierAndOffset.Offset is not in increasing order.')
                    property = data[self.PropertyIdentifierAndOffset[i].Offset:self.Size]
            else:
                property = data[self.PropertyIdentifierAndOffset[i].Offset:self.Size]
            self.Property.append(property)
        
        for i in range(0, self.NumProperties):
            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_CODEPAGE']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_CODEPAGE.type: ' + str(hex(type)))
                if type != PropertyType['VT_I2']:
                    self._raise_exception('Property.GKPIDDSI_CODEPAGE has an abnormal value.')
                codepage = struct.unpack('<H', self.Property[i][0x04:0x06])[0]
                self.ole_logger.debug('Property.GKPIDDSI_CODEPAGE: ' + str(hex(codepage)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_COMPANY']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_COMPANY.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.GKPIDDSI_COMPANY.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.GKPIDDSI_COMPANY.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    company = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    company = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.GKPIDDSI_COMPANY has an abnormal value.')
                self.ole_logger.debug('Property.GKPIDDSI_COMPANY: ' + company)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_LINECOUNT']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_LINECOUNT.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.GKPIDDSI_LINECOUNT has an abnormal value.')
                linecount = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.GKPIDDSI_LINECOUNT: ' + str(hex(linecount)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_PARACOUNT']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_PARACOUNT.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.GKPIDDSI_PARACOUNT has an abnormal value.')
                pagecount = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.GKPIDDSI_PARACOUNT: ' + str(hex(pagecount)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_CCHWITHSPACES']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_CCHWITHSPACES.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.GKPIDDSI_CCHWITHSPACES has an abnormal value.')
                pagecount = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.GKPIDDSI_CCHWITHSPACES: ' + str(hex(pagecount)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_VERSION']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_VERSION.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.GKPIDDSI_VERSION has an abnormal value.')
                minorversion = struct.unpack('<H', self.Property[i][0x04:0x06])[0]
                majorverson= struct.unpack('<H', self.Property[i][0x06:0x08])[0]
                if majorverson == 0:
                    self._raise_exception('Property.GKPIDDSI_VERSION.MajorVersion has an abnormal value.')
                self.ole_logger.debug('Property.GKPIDDSI_VERSION.MajorVersion: ' + str(hex(majorverson)))
                self.ole_logger.debug('Property.GKPIDDSI_VERSION.MinorVersion: ' + str(hex(minorversion)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_DOCPARTS']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_DOCPARTS.type: ' + str(hex(type)))
                celements = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.GKPIDDSI_DOCPARTS.vtValue.cElements: ' + str(hex(celements)))
                if type == (PropertyType['VT_VECTOR'] | PropertyType['VT_LPSTR']):           
                    offset = 0
                    for j in range(0, celements):
                        cch = struct.unpack('<I', self.Property[i][0x08+offset:0x0C+offset])[0]
                        self.ole_logger.debug('Property.GKPIDDSI_DOCPARTS.vtValue.rgString[' + str(j) + '].cch: ' + str(hex(cch)))
                        if cch > 0x0000FFFF:
                            self._raise_exception('Property.GKPIDDSI_DOCPARTS.vtValue.rgString[' + str(j) + '].cch has an abnormal value.')
                        value = self.Property[i][0x0C+offset:0x0C+offset+cch]
                        self.ole_logger.debug('Property.GKPIDDSI_DOCPARTS.vtValue.rgString[' + str(j) + ']: ' + value.encode('hex'))
                        offset = offset + 4 + cch
                elif type == (PropertyType['VT_VECTOR'] | PropertyType['VT_LPWSTR']):
                    offset = 0
                    for j in range(0, celements):
                        cch = struct.unpack('<I', self.Property[i][0x08+offset:0x0C+offset])[0]
                        self.ole_logger.debug('Property.GKPIDDSI_DOCPARTS.vtValue.rgString[' + str(j) + '].cch: ' + str(hex(cch)))
                        if cch > 0x0000FFFF:
                            self._raise_exception('Property.GKPIDDSI_DOCPARTS.vtValue.rgString[' + str(j) + '].cch has an abnormal value.')
                        value = self.Property[i][0x0C+offset:0x0C+offset+cch*2].decode('utf-16')
                        self.ole_logger.debug('Property.GKPIDDSI_DOCPARTS.vtValue.rgString[' + str(j) + ']: ' + value.encode('hex'))
                        offset = offset + 4 + cch*2
                else:
                    self._raise_exception('Property.GKPIDDSI_DOCPARTS.type has an abnormal value.')
                continue
                
            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDDSI['GKPIDDSI_HEADINGPAIR']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.type: ' + str(hex(type)))
                if type != (PropertyType['VT_VECTOR'] | PropertyType['VT_VARIANT']):
                    self._raise_exception('Property.GKPIDDSI_HEADINGPAIR.type has an abnormal value.')
                celements = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.cElements: ' + str(hex(celements)))
                offset = 0
                for j in range(0, celements/2):
                    strtype = struct.unpack('<H', self.Property[i][0x08+offset:0x0A+offset])[0]
                    self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headingString.type: ' + str(hex(strtype)))
                    cch = struct.unpack('<I', self.Property[i][0x0C+offset:0x10+offset])[0]
                    self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headingString.cch: ' + str(hex(cch)))
                    if cch > 0x0000FFFF:
                            self._raise_exception('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headingString.cch has an abnormal value.')
                    if strtype == PropertyType['VT_LPSTR']:
                        value = self.Property[i][0x10+offset:0x10+offset+cch]
                        self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headingString: ' + value)
                        partstype = struct.unpack('<H', self.Property[i][0x10+offset+cch:0x10+offset+cch+0x02])[0]
                        self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headerParts.type: ' + str(hex(partstype)))
                        if partstype != PropertyType['VT_I4']:
                            self._raise_exception('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headerParts.type has an abnormal value.')
                        parts = struct.unpack('<I', self.Property[i][0x10+offset+cch+0x04:0x10+offset+cch+0x08])[0]
                        self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headerParts: ' + str(hex(parts)))
                        offset = offset + 0x10 + cch
                    elif strtype == PropertyType['VT_LPWSTR']:
                        value = self.Property[i][0x10+offset:0x10+offset+cch*2].decode('utf-16')
                        self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headingString: ' + value)
                        partstype = struct.unpack('<H', self.Property[i][0x10+offset+cch*2:0x10+offset+cch*2+0x02])[0]
                        self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headerParts.type: ' + str(hex(partstype)))
                        if partstype != PropertyType['VT_I4']:
                            self._raise_exception('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headerParts.type has an abnormal value.')
                        parts = struct.unpack('<I', self.Property[i][0x10+offset+cch*2+0x04:0x10+offset+cch*2+0x08])[0]
                        self.ole_logger.debug('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headerParts: ' + str(hex(parts)))
                        offset = offset + 0x10 + cch*2
                    else:
                        self._raise_exception('Property.GKPIDDSI_HEADINGPAIR.vtValue.rgHeadingPairs[' + str(j) + '].headingString.type has an abnormal value.')
                continue


class DocSummaryInfo(OLEBase):

    byteOrder = 0
    version = 0
    sysId = 0
    OSMajorVersion = 0
    OSMinorVersion = 0
    OSType = 0
    applicationClsid = ''
    cSections = 0
    formatId1 = ''
    sectionOffset1 = 0
    formatId2 = ''
    sectionOffset2 = 0
    DocumentSummaryInfoPropertySet = None

    def __init__(self, data):

        self.byteOrder = 0
        self.version = 0
        self.sysId = 0
        self.OSMajorVersion = 0
        self.OSMinorVersion = 0
        self.OSType = 0
        self.applicationClsid = ''
        self.cSections = 0
        self.formatId1 = ''
        self.sectionOffset1 = 0
        self.formatId2 = ''
        self.sectionOffset2 = 0
        self.DocumentSummaryInfoPropertySet = None

        self.ole_logger.debug('######## DocumentSummaryInfo ########')

        self.byteOrder = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('DocumentSummaryInfo.byteOrder: ' + str(hex(self.byteOrder)))
        if self.byteOrder != 0xFFFE:
            self._raise_exception('DocumentSummaryInfo.byteOrder has an abnormal value.')

        self.version = struct.unpack('<H', data[0x02:0x04])[0]
        self.ole_logger.debug('DocumentSummaryInfo.version: ' + str(hex(self.version)))
        if self.version != 0 and self.version != 1:
            self._raise_exception('DocumentSummaryInfo.version has an abnormal value.')

        self.sysId = struct.unpack('<I', data[0x04:0x08])[0]
        self.OSMajorVersion = ord(data[0x04])
        self.ole_logger.debug('DocumentSummaryInfo.sysId.OSMajorVersion: ' + str(hex(self.OSMajorVersion)))
        self.OSMinorVersion = ord(data[0x05])
        self.ole_logger.debug('DocumentSummaryInfo.sysId.OSMinorVersion: ' + str(hex(self.OSMinorVersion)))
        self.OSType = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('DocumentSummaryInfo.sysId.OSType: ' + str(hex(self.OSType)))

        self.applicationClsid = data[0x08:0x18]
        self.ole_logger.debug('DocumentSummaryInfo.applicationClsid: ' + self.applicationClsid.encode('hex'))
        if self.applicationClsid != '\x00' * 0x10:
            self._raise_exception('DocumentSummaryInfo.applicationClsid has an abnormal value.')

        self.cSections = struct.unpack('<I', data[0x18:0x1C])[0]
        self.ole_logger.debug('DocumentSummaryInfo.cSections: ' + str(hex(self.cSections)))
        if self.cSections != 1 and self.cSections != 2:
            self._raise_exception('DocumentSummaryInfo.cSections has an abnormal value.')

        self.formatId1 = data[0x1C:0x2C]
        self.ole_logger.debug('DocumentSummaryInfo.rgIdOffset.IdOffsetElement-1.formatId: ' + self.formatId1.encode('hex'))
        if self.formatId1 != '\x02\xD5\xCD\xD5\x9C\x2E\x1B\x10\x93\x97\x08\x00\x2B\x2C\xF9\xAE':
            self._raise_exception('DocumentSummaryInfo.rgIdOffset.IdOffsetElement-1.formatId has an abnormal value.')

        self.sectionOffset1 = struct.unpack('<I', data[0x2C:0x30])[0]
        self.ole_logger.debug('DocumentSummaryInfo.rgIdOffset.IdOffsetElement-1.sectionOffset: ' + str(hex(self.sectionOffset1)))

        if self.cSections == 2:
            self.formatId2 = data[0x30:0x40]
            self.ole_logger.debug('DocumentSummaryInfo.rgIdOffset.IdOffsetElement-2.formatId: ' + self.formatId2.encode('hex'))
            if self.formatId2 != '\x05\xD5\xCD\xD5\x9C\x2E\x1B\x10\x93\x97\x08\x00\x2B\x2C\xF9\xAE':
                self._raise_exception('DocumentSummaryInfo.rgIdOffset.IdOffsetElement-2.formatId has an abnormal value.')

            self.sectionOffset2 = struct.unpack('<I', data[0x40:0x44])[0]
            self.ole_logger.debug('DocumentSummaryInfo.rgIdOffset.IdOffsetElement-2.sectionOffset: ' + str(hex(self.sectionOffset2)))

        self.DocumentSummaryInfoPropertySet = DocSummaryInfoPropertySet(data[self.sectionOffset1:])


class SummaryInfoPropertySet(OLEBase):

    Size = 0
    NumProperties = 0
    PropertyIdentifierAndOffset = list()
    Property = list()

    def __init__(self, data):
        
        self.Size = 0
        self.NumProperties = 0
        self.PropertyIdentifierAndOffset = list()
        self.Property = list()

        self.Size = struct.unpack('<I', data[0x00:0x04])[0]
        self.ole_logger.debug('SummaryInfoPropertySet.Size: ' + str(hex(self.Size)))

        self.NumProperties = struct.unpack('<I', data[0x04:0x08])[0]
        self.ole_logger.debug('SummaryInfoPropertySet.NumProperties: ' + str(hex(self.NumProperties)))

        for i in range(0, self.NumProperties):
            piao = PropertyIdentifierAndOffset(data[0x08+i*8:0x08+i*8+8])
            self.PropertyIdentifierAndOffset.append(piao)

        for i in range(0, self.NumProperties):
            if (i+1) < self.NumProperties:
                if self.PropertyIdentifierAndOffset[i].Offset < self.PropertyIdentifierAndOffset[i+1].Offset:
                    property = data[self.PropertyIdentifierAndOffset[i].Offset:self.PropertyIdentifierAndOffset[i+1].Offset]
                else:
                    self.ole_logger.warning('SummaryInfoPropertySet.PropertyIdentifierAndOffset.Offset is not in increasing order.')
                    property = data[self.PropertyIdentifierAndOffset[i].Offset:self.Size]
            else:
                property = data[self.PropertyIdentifierAndOffset[i].Offset:self.Size]
            self.Property.append(property)
        
        for i in range(0, self.NumProperties):
            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_CODEPAGE']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_CODEPAGE.type: ' + str(hex(type)))
                if type != PropertyType['VT_I2']:
                    self._raise_exception('Property.PIDSI_CODEPAGE has an abnormal value.')
                codepage = struct.unpack('<H', self.Property[i][0x04:0x06])[0]
                self.ole_logger.debug('Property.PIDSI_CODEPAGE: ' + str(hex(codepage)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_TITLE']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_TITLE.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_TITLE.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_TITLE.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_TITLE has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_TITLE: ' + data)
                continue
            
            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_SUBJECT']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_SUBJECT.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_SUBJECT.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_SUBJECT.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_SUBJECT has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_SUBJECT: ' + data)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_AUTHOR']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_AUTHOR.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_AUTHOR.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_AUTHOR.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_AUTHOR has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_AUTHOR: ' + data)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_KEYWORDS']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_KEYWORDS.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_KEYWORDS.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_KEYWORDS.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_KEYWORDS has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_KEYWORDS: ' + data)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_COMMENTS']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_COMMENTS.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_COMMENTS.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_COMMENTS.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_COMMENTS has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_COMMENTS: ' + data)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_TEMPLATE']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_TEMPLATE.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_TEMPLATE.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_TEMPLATE.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_TEMPLATE has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_TEMPLATE: ' + data)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_LASTAUTHOR']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_LASTAUTHOR.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_LASTAUTHOR.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_LASTAUTHOR.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_LASTAUTHOR has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_LASTAUTHOR: ' + data)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_REVNUMBER']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_REVNUMBER.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_REVNUMBER.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_REVNUMBER.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_REVNUMBER has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_REVNUMBER: ' + data)
                continue
            
            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_APPNAME']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_APPNAME.type: ' + str(hex(type)))
                cch = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_APPNAME.cch: ' + str(hex(cch)))
                if cch > 0x0000FFFF:
                        self._raise_exception('Property.PIDSI_APPNAME.cch has an abnormal value.')
                if type == PropertyType['VT_LPSTR']:
                    data = self.Property[i][0x08:0x08+cch]
                elif type == PropertyType['VT_LPWSTR']:
                    data = self.Property[i][0x08:0x08+cch*2].decode('utf-16')
                else:
                    self._raise_exception('Property.PIDSI_APPNAME has an abnormal value.')
                self.ole_logger.debug('Property.PIDSI_APPNAME: ' + data)
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_EDITTIME']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_APPNAME.type: ' + str(hex(type)))
                if type != PropertyType['VT_FILETIME']:
                    self._raise_exception('Property.PIDSI_EDITTIME has an abnormal value.')
                time = struct.unpack('<Q', self.Property[i][0x04:0x0C])[0]
                self.ole_logger.debug('Property.PIDSI_EDITTIME: ' + str(hex(time)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_LASTPRINTED']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_LASTPRINTED.type: ' + str(hex(type)))
                if type != PropertyType['VT_FILETIME']:
                    self._raise_exception('Property.PIDSI_LASTPRINTED has an abnormal value.')
                time = struct.unpack('<Q', self.Property[i][0x04:0x0C])[0]
                self.ole_logger.debug('Property.PIDSI_LASTPRINTED: ' + self._filetime_to_datetime(time))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_CREATE_DTM']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_CREATE_DTM.type: ' + str(hex(type)))
                if type != PropertyType['VT_FILETIME']:
                    self._raise_exception('Property.PIDSI_CREATE_DTM has an abnormal value.')
                time = struct.unpack('<Q', self.Property[i][0x04:0x0C])[0]
                self.ole_logger.debug('Property.PIDSI_CREATE_DTM: ' + self._filetime_to_datetime(time))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_LASTSAVE_DTM']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_LASTSAVE_DTM.type: ' + str(hex(type)))
                if type != PropertyType['VT_FILETIME']:
                    self._raise_exception('Property.PIDSI_LASTSAVE_DTM has an abnormal value.')
                time = struct.unpack('<Q', self.Property[i][0x04:0x0C])[0]
                self.ole_logger.debug('Property.PIDSI_LASTSAVE_DTM: ' + self._filetime_to_datetime(time))
                continue
            
            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_PAGECOUNT']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_PAGECOUNT.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.PIDSI_PAGECOUNT has an abnormal value.')
                count = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_PAGECOUNT: ' + str(hex(count)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_WORDCOUNT']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_WORDCOUNT.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.PIDSI_WORDCOUNT has an abnormal value.')
                count = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_WORDCOUNT: ' + str(hex(count)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_CHARCOUNT']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_CHARCOUNT.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.PIDSI_CHARCOUNT has an abnormal value.')
                count = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_CHARCOUNT: ' + str(hex(count)))
                continue

            if self.PropertyIdentifierAndOffset[i].PropertyIdentifier == PIDSI['PIDSI_DOC_SECURITY']:
                type = struct.unpack('<H', self.Property[i][0x00:0x02])[0]
                self.ole_logger.debug('Property.PIDSI_DOC_SECURITY.type: ' + str(hex(type)))
                if type != PropertyType['VT_I4']:
                    self._raise_exception('Property.PIDSI_DOC_SECURITY has an abnormal value.')
                security = struct.unpack('<I', self.Property[i][0x04:0x08])[0]
                self.ole_logger.debug('Property.PIDSI_DOC_SECURITY: ' + str(hex(security)))
                continue


class SummaryInfo(OLEBase):

    byteOrder = 0
    version = 0
    sysId = 0
    OSMajorVersion = 0
    OSMinorVersion = 0
    OSType = 0
    applicationClsid = ''
    cSections = 0
    formatId1 = ''
    sectionOffset1 = 0
    formatId2 = ''
    sectionOffset2 = 0
    SummaryInfoPropertySet = None

    def __init__(self, data):

        self.byteOrder = 0
        self.version = 0
        self.sysId = 0
        self.OSMajorVersion = 0
        self.OSMinorVersion = 0
        self.OSType = 0
        self.applicationClsid = ''
        self.cSections = 0
        self.formatId1 = ''
        self.sectionOffset1 = 0
        self.formatId2 = ''
        self.sectionOffset2 = 0
        self.SummaryInfoPropertySet = None

        self.ole_logger.debug('######## SummaryInfo ########')

        self.byteOrder = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('SummaryInfo.byteOrder: ' + str(hex(self.byteOrder)))
        if self.byteOrder != 0xFFFE:
            self._raise_exception('DocumentSummaryInfo.byteOrder has an abnormal value.')

        self.version = struct.unpack('<H', data[0x02:0x04])[0]
        self.ole_logger.debug('SummaryInfo.version: ' + str(hex(self.version)))
        if self.version != 0 and self.version != 1:
            self._raise_exception('SummaryInfo.version has an abnormal value.')

        self.sysId = struct.unpack('<I', data[0x04:0x08])[0]
        self.ole_logger.debug('SummaryInfo.sysId: ' + str(hex(self.sysId)))

        self.clsid = data[0x08:0x18]
        self.ole_logger.debug('SummaryInfo.clsid: ' + self.clsid.encode('hex'))
        if self.clsid != '\x00' * 0x10:
            self._raise_exception('SummaryInfo.clsid has an abnormal value.')

        self.cSections = struct.unpack('<I', data[0x18:0x1C])[0]
        self.ole_logger.debug('SummaryInfo.cSections: ' + str(hex(self.cSections)))
        if self.cSections != 1 and self.cSections != 2:
            self._raise_exception('SummaryInfo.cSections has an abnormal value.')

        self.formatId1 = data[0x1C:0x2C]
        self.ole_logger.debug('SummaryInfo.rgIdOffset.IdOffsetElement-1.formatId: ' + self.formatId1.encode('hex'))
        if self.formatId1 != '\xE0\x85\x9F\xF2\xF9\x4F\x68\x10\xAB\x91\x08\x00\x2B\x27\xB3\xD9':
            self._raise_exception('SummaryInfo.rgIdOffset.IdOffsetElement-1.formatId has an abnormal value.')

        self.sectionOffset1 = struct.unpack('<I', data[0x2C:0x30])[0]
        self.ole_logger.debug('DocumentSummaryInfo.rgIdOffset.IdOffsetElement-1.sectionOffset: ' + str(hex(self.sectionOffset1)))

        if self.cSections == 2:
            self.formatId2 = data[0x30:0x40]
            self.ole_logger.debug('SummaryInfo.rgIdOffset.IdOffsetElement-2.formatId: ' + self.formatId2.encode('hex'))
            if self.formatId2 != '\x05\xD5\xCD\xD5\x9C\x2E\x1B\x10\x93\x97\x08\x00\x2B\x2C\xF9\xAE':
                self._raise_exception('SummaryInfo.rgIdOffset.IdOffsetElement-2.formatId has an abnormal value.')

            self.sectionOffset2 = struct.unpack('<I', data[0x40:0x44])[0]
            self.ole_logger.debug('SummaryInfo.rgIdOffset.IdOffsetElement-2.sectionOffset: ' + str(hex(self.sectionOffset2)))

        self.SummaryInfoPropertySet = SummaryInfoPropertySet(data[self.sectionOffset1:])


class OLEFile(OLEBase):

    file_data = None
    sector_size = 0
    mini_sector_size = 0

    OLEHeader = None
    DIFAT = list()
    FAT = list()
    MiniFAT = list()
    Directory = list()
    SummaryInfo = None
    DocumentSummaryInfo = None


    def __init__(self, filename):
        
        self.file_data = None
        self.sector_size = 0
        self.mini_sector_size = 0
        
        self.OLEHeader = None
        self.DIFAT = list()
        self.FAT = list()
        self.MiniFAT = list()
        self.Directory = list()
        self.SummaryInfo = None
        self.DocumentSummaryInfo = None
        
        
        if os.path.isfile(filename):
            self.file_data = open(filename, 'rb').read()
            self.ole_logger.debug('Load file: ' + filename)

            self.OLEHeader = OLEHeader(self.file_data)

            if self.OLEHeader.SectorShift == 0x09:
                self.sector_size = 512
            elif self.OLEHeader.SectorShift == 0x0C:
                self.sector_size = 4096
            else:
                self._raise_exception('Invalid Sector Size.')

            if self.OLEHeader.MiniSectorShift == 0x06:
                self.mini_sector_size = 64
            else:
                self._raise_exception('Invalid MiniSector Size.')

            self._init_fat_chain()
            
            if self.OLEHeader.NumberOfMiniFATSectors > 0:
                self._init_minifat_chain()

            self._init_dir_entry()


            for i in range(0, len(self.Directory)):
                if self.Directory[i].Name == '\x05SummaryInformation':
                    self.SummaryInfo = SummaryInfo(self.find_object_by_index(i))

                if self.Directory[i].Name == '\x05DocumentSummaryInformation':
                    self.DocumentSummaryInfo = DocSummaryInfo(self.find_object_by_index(i))
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
            self.ole_logger.warn('OLEHeader.NumberOfFATSectors does not mahtch the number of the DIFAT entries.')
        
        for i in range(0, self.OLEHeader.NumberOfFATSectors):
            fat_sector_index = self.DIFAT[i]
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
        i = 0
        while i < self.OLEHeader.NumberOfMiniFATSectors:
            minifat_sector_offset = (minifat_sector_index+1) * self.sector_size
            self.ole_logger.debug('MiniFAT sector #' + str(i) + ' at offset: ' + str(hex(minifat_sector_offset)))
            for j in range(0, self.sector_size/4):
                minifat = struct.unpack('<I', self.file_data[minifat_sector_offset+j*4:minifat_sector_offset+j*4+4])[0]
                self.MiniFAT.append(minifat) 
            minifat_sector_index = self.FAT[minifat_sector_index]
            if minifat_sector_index == 0xFFFFFFFE:
                self.ole_logger.debug('MiniFAT sector chain ended.')
                break
            i += 1
            
        if (i+1) != self.OLEHeader.NumberOfMiniFATSectors:
            self.ole_logger.warn('self.OLEHeader.NumberOfMiniFATSectors does not match the length of the MiniFat sector chian.')     
    

    def _init_dir_entry(self):
        dir_sector_index = self.OLEHeader.FirstDirecotrySector
        is_end = False
        while True:
            dir_sector_offset = (dir_sector_index+1) * self.sector_size
            for i in range(0, self.sector_size/128):
                if (dir_sector_offset+i*128+128) > len(self.file_data):
                    self.ole_logger.warning('Direcotry sector offset larger than file size.')
                    is_end = True
                    break
                dir_data = self.file_data[dir_sector_offset+i*128:dir_sector_offset+i*128+128]
                if struct.unpack('<H', dir_data[0x40:0x42])[0] == 0:
                    is_end = True
                    break
                self.ole_logger.debug('[----- Directory #' + str(len(self.Directory)) + ' -----]')
                try:
                    directory = Directory(dir_data)    
                    self.Directory.append(directory)
                except:
                    self.ole_logger.debug('Directory #' + str(len(self.Directory)) + ' contains abnormal structure.')
            dir_sector_index = self.FAT[dir_sector_index]
            if is_end or dir_sector_index == 0xFFFFFFFE:
                break
    
    
    def find_object_by_name(self, name):
        data = ''
        dir_number = len(self.Directory)
        
        for i in range(0, dir_number):
            directory = self.Directory[i]
            if name == directory.Name:

                if directory.ObjectType != 0x02 and directory.ObjectType != 0x05:
                    return directory
                
                sector_index = directory.StartingSector
                if sector_index == 0xFFFFFFFE:
                    self.ole_logger.debug('Object: ' + name + ' has no data.')
                    return None

                if directory.StreamSize < self.OLEHeader.MiniStreamCutoffSize and len(self.MiniFAT) > 0 and name != 'Root Entry':
                    ministream = self.find_object_by_name('Root Entry')
                    if len(ministream) > 0:
                        while sector_index != 0xFFFFFFFE:
                            sector_offset = sector_index * 0x40
                            data += ministream[sector_offset:sector_offset+0x40]
                            sector_index = self.MiniFAT[sector_index]
                    else:
                        self.ole_logger.debug('Mini Stream is null.')
                        return None
                else:
                    while sector_index != 0xFFFFFFFE:
                        sector_offset = (sector_index+1) * self.sector_size
                        data += self.file_data[sector_offset:sector_offset+self.sector_size]
                        sector_index = self.FAT[sector_index]
                break
        
        if (i+1) == dir_number:
            self.ole_logger.debug('Could not find object: ' + name)
            return None

        if directory.StreamSize > len(data):
            self.ole_logger.warn('DirectoryEntry.StreamSize larger than real data size.')
            return None
            
        return data[0: directory.StreamSize]

    
    def find_object_by_index(self, index):
        data = ''
        
        if index < 0 or index >= len(self.Directory):
            self.ole_logger.warn('Index out of boundary.')
            return None
            
        directory = self.Directory[index]

        if directory.ObjectType != 0x02 and directory.ObjectType != 0x05:
            return directory

        sector_index = directory.StartingSector
        if sector_index == 0xFFFFFFFE:
            self.ole_logger.debug('Object #' + str(index) + ' has no data.')
            return None

        if directory.StreamSize < self.OLEHeader.MiniStreamCutoffSize and len(self.MiniFAT) > 0:
            ministream = self.find_object_by_name('Root Entry')
            if len(ministream) > 0:
                while sector_index != 0xFFFFFFFE:
                    sector_offset = sector_index * 0x40
                    data += ministream[sector_offset:sector_offset+0x40]
                    sector_index = self.MiniFAT[sector_index]
            else:
                self.ole_logger.debug('Mini Stream is null.')
                return None
        else:
            while sector_index != 0xFFFFFFFE:
                sector_offset = (sector_index+1) * self.sector_size
                data += self.file_data[sector_offset:sector_offset+self.sector_size]
                sector_index = self.FAT[sector_index]

        if directory.StreamSize > len(data):
            self.ole_logger.warn('DirectoryEntry.StreamSize larger than real data size.')
            return None
            
        return data[0: directory.StreamSize]


if __name__ == '__main__':
    debug = True
    init_logging(debug)

    

   
    
    

