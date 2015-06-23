# A simple DOC file parser based on pyole

import os
import struct
import logging
from pyole import *


class FIBBase(OLEBase):

    wIdent = 0
    nFib = 0
    unused = 0
    lid = 0
    pnNext = 0
    Flags1 = 0
    fDot = 0
    fGlsy = 0
    fComplex = 0
    fHasPic = 0
    cQuickSaves = 0
    fEncrypted = 0
    fWhichTblStm = 0
    fReadOnlyRecommended = 0
    fWriteReservation = 0
    fExtChar = 0
    fLoadOverride = 0
    fFarEast = 0
    fObfuscated = 0
    nFibBack  = 0
    lKey = 0
    envr = 0
    Flag2 = 0
    fMac = 0
    fEmptySpecial = 0
    fLoadOverridePage = 0
    reserved1 = 0
    reserved2 = 0
    fSpare0 = 0
    reserved3 = 0
    reserved4 = 0
    reserved5 = 0
    reserved6 = 0

    def __init__(self, data):

        self.wIdent  = 0
        self.nFib = 0
        self.unused = 0
        self.pnNext = 0
        self.Flags1 = 0
        self.fDot = 0
        self.fGlsy = 0
        self.fComplex = 0
        self.fHasPic = 0
        self.cQuickSaves = 0
        self.fEncrypted = 0
        self.fWhichTblStm = 0
        self.fReadOnlyRecommended = 0
        self.fWriteReservation = 0
        self.fExtChar = 0
        self.fLoadOverride = 0
        self.fFarEast = 0
        self.fObfuscated = 0
        self.nFibBack  = 0
        self.lKey = 0
        self.envr = 0
        self.Flag2 = 0
        self.fMac = 0
        self.fEmptySpecial = 0
        self.fLoadOverridePage = 0
        self.reserved1 = 0
        self.reserved2 = 0
        self.fSpare0 = 0
        self.reserved3 = 0
        self.reserved4 = 0
        self.reserved5 = 0
        self.reserved6 = 0
        
        self.wIdent = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.wIdent: ' + str(hex(self.wIdent)))
        if self.wIdent != 0xA5EC:
            self._raise_exception('DOC.FIB.FIBBase.wIdent has an abnormal value.')

        self.nFib = struct.unpack('<H', data[0x02:0x04])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.nFib: ' + str(hex(self.nFib)))
        if self.nFib != 0x00C1:
            self._raise_exception('DOC.FIB.FIBBase.nFib has an abnormal value.')
        
        self.unused  = struct.unpack('<H', data[0x04:0x06])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.unused: ' + str(hex(self.unused)))
        if self.unused != 0:
            self.ole_logger.warning('DOC.FIB.FIBBase.unused is not zero.')

        self.lid = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.lid: ' + str(hex(self.lid)))

        self.pnNext  = struct.unpack('<H', data[0x08:0x0A])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.pnNext: ' + str(hex(self.pnNext)))
        if self.pnNext != 0:
            self.ole_logger.warning('DOC.FIB.FIBBase.pnNext is not zero.')

        self.Flags1 = struct.unpack('<H', data[0x0A:0x0C])[0]
        self.fDot = self.Flags1 & 0x0001
        self.ole_logger.debug('DOC.FIB.FIBBase.fDot: ' + str(self.fDot))
        self.fGlsy = (self.Flags1 & 0x0002) >> 1
        self.ole_logger.debug('DOC.FIB.FIBBase.fGlsy: ' + str(self.fGlsy))
        self.fComplex = (self.Flags1 & 0x0004) >> 2
        self.ole_logger.debug('DOC.FIB.FIBBase.fComplex: ' + str(self.fComplex))
        self.fHasPic = (self.Flags1 & 0x0008) >> 3
        self.ole_logger.debug('DOC.FIB.FIBBase.fHasPic: ' + str(self.fHasPic))
        self.cQuickSaves = (self.Flags1 & 0x00F0) >> 4
        self.ole_logger.debug('DOC.FIB.FIBBase.cQuickSaves: ' + str(self.cQuickSaves))
        self.fEncrypted = (self.Flags1 & 0x0100) >> 8
        self.ole_logger.debug('DOC.FIB.FIBBase.fEncrypted: ' + str(self.fEncrypted))
        if self.fEncrypted == 1:
            self.ole_logger.warning('File is encrypted.')
        self.fWhichTblStm = (self.Flags1 & 0x0200) >> 9
        self.ole_logger.debug('DOC.FIB.FIBBase.fWhichTblStm: ' + str(self.fWhichTblStm))
        self.fReadOnlyRecommended = (self.Flags1 & 0x0400) >> 10
        self.ole_logger.debug('DOC.FIB.FIBBase.fReadOnlyRecommended: ' + str(self.fReadOnlyRecommended))
        self.fWriteReservation = (self.Flags1 & 0x0800) >> 11
        self.ole_logger.debug('DOC.FIB.FIBBase.fWriteReservation: ' + str(self.fWriteReservation))
        self.fExtChar = (self.Flags1 & 0x1000) >> 12
        self.ole_logger.debug('DOC.FIB.FIBBase.fExtChar: ' + str(self.fExtChar))
        if (self.Flags1 & 0x1000) >> 12 != 1:
            self._raise_exception('DOC.FIB.FIBBase.fExtChar has an abnormal value.')
        self.fLoadOverride = (self.Flags1 & 0x2000) >> 13
        self.ole_logger.debug('DOC.FIB.FIBBase.fLoadOverride: ' + str(self.fLoadOverride))
        self.fFarEast = (self.Flags1 & 0x4000) >> 14
        self.ole_logger.debug('DOC.FIB.FIBBase.fFarEast: ' + str(self.fFarEast))
        if self.fFarEast == 1:
            self.ole_logger.warning('The installation language of the application that created the document was an East Asian language.')
        self.fObfuscated = (self.Flags1 & 0x8000) >> 15
        self.ole_logger.debug('DOC.FIB.FIBBase.fObfuscated: ' + str(self.fObfuscated))
        if self.fObfuscated == 1:
            if self.fEncrypted == 1:
                self.ole_logger.warning('File is obfuscated by using XOR obfuscation.')
                
        self.nFibBack = struct.unpack('<H', data[0x0C:0x0E])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.nFibBack: ' + str(hex(self.nFibBack)))
        if self.nFibBack != 0x00BF and self.nFibBack != 0x00C1:
            self._raise_exception('DOC.FIB.FIBBase.nFibBack has an abnormal value.')

        self.lKey = struct.unpack('<I', data[0x0E:0x12])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.lKey: ' + str(hex(self.lKey)))
        if self.fEncrypted == 1:
            if self.fObfuscated == 1:
                self.ole_logger.info('The XOR obfuscation key is: ' + str(hex(self.lKey)))
        else:
            if self.lKey != 0:
                self._raise_exception('DOC.FIB.FIBBase.lKey has an abnormal value.')

        self.envr = ord(data[0x12])
        self.ole_logger.debug('DOC.FIB.FIBBase.envr: ' + str(hex(self.envr)))
        if self.envr != 0:
            self._raise_exception('DOC.FIB.FIBBase.envr has an abnormal value.')

        self.Flag2 = ord(data[0x13])
        self.fMac = self.Flag2 & 0x01
        self.ole_logger.debug('DOC.FIB.FIBBase.fMac: ' + str(hex(self.fMac)))
        if self.fMac != 0:
            self._raise_exception('DOC.FIB.FIBBase.fMac has an abnormal value.')
        self.fEmptySpecial = (self.Flag2 & 0x02) >> 1
        self.ole_logger.debug('DOC.FIB.FIBBase.fEmptySpecial: ' + str(hex(self.fEmptySpecial)))
        if self.fEmptySpecial != 0:
            self.ole_logger.warning('DOC.FIB.FIBBase.fEmptySpecial is not zero.')
        self.fLoadOverridePage = (self.Flag2 & 0x04) >> 2
        self.ole_logger.debug('DOC.FIB.FIBBase.fLoadOverridePage: ' + str(hex(self.fLoadOverridePage)))
        self.reserved1 = (self.Flag2 & 0x08) >> 3
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved1: ' + str(hex(self.reserved1)))
        self.reserved2 = (self.Flag2 & 0x10) >> 4
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved2: ' + str(hex(self.reserved2)))
        self.fSpare0 = (self.Flag2 & 0xE0) >> 5
        self.ole_logger.debug('DOC.FIB.FIBBase.fSpare0: ' + str(hex(self.fSpare0)))

        self.reserved3 = struct.unpack('<H', data[0x14:0x16])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved3: ' + str(hex(self.reserved3)))
        self.reserved4 = struct.unpack('<H', data[0x16:0x18])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved4: ' + str(hex(self.reserved4)))
        self.reserved5 = struct.unpack('<I', data[0x18:0x1C])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved5: ' + str(hex(self.reserved5)))
        self.reserved6 = struct.unpack('<I', data[0x1C:0x20])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved6: ' + str(hex(self.reserved6)))


class FIB(OLEBase):

    FIBBase = None
    csw = 0
    fibRgW = ''
    cslw = 0
    fibRgLw = ''
    cbRgFcLcb = 0

    def __init__(self, data):
        
        self.FIBBase = None
        self.csw = 0
        self.fibRgW = ''
        self.cslw = 0
        self.fibRgLw = ''
        self.cbRgFcLcb = 0

        self.ole_logger.debug('######## FIB ########')
        
        self.FIBBase = FIBBase(data[0:0x20])
        
        self.csw = struct.unpack('<H', data[0x20:0x22])[0]
        self.ole_logger.debug('DOC.FIB.csw: ' + str(hex(self.csw)))
        if self.csw != 0x000E:
            self._raise_exception('DOC.FIB.csw has an abnormal value.')

        self.fibRgW = data[0x22:0x3E]
        
        self.cslw = struct.unpack('<H', data[0x3E:0x40])[0]
        self.ole_logger.debug('DOC.FIB.cslw: ' + str(hex(self.cslw)))
        if self.cslw != 0x0016:
            self._raise_exception('DOC.FIB.cslw has an abnormal value.')
        
        self.fibRgLw = data[0x40:0x98]

        self.cbRgFcLcb = struct.unpack('<H', data[0x98:0x9A])[0]
        self.ole_logger.debug('DOC.FIB.cbRgFcLcb: ' + str(hex(self.cbRgFcLcb)))
        '''
        if self.FIBBase.nFib == 0x00C1 and self.cbRgFcLcb != 0x005D:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x00D9 and self.cbRgFcLcb != 0x006C:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x0101 and self.cbRgFcLcb != 0x0088:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x010C and self.cbRgFcLcb != 0x00A4:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x0112 and self.cbRgFcLcb != 0x00B7:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        '''


class DocSummaryInfo(OLEBase):

    byteOrder = 0
    version = 0
    sysId = 0
    OSMajorVersion = 0
    OSMinorVersion = 0
    OSType = 0
    applicationClsid = ''
    cSections = 0

    def __init__(self, data):

        self.byteOrder = 0
        self.version = 0
        self.sysId = 0
        self.OSMajorVersion = 0
        self.OSMinorVersion = 0
        self.OSType = 0
        self.applicationClsid = ''
        self.cSections = 0

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

class DOCFile(OLEBase):

    OLE = None
    FIB = None
    DocumentSummaryInfo = None

    def __init__(self, filename):
        self.OLE = None
        self.FIB = None
        self.DocumentSummaryInfo = None

        if os.path.isfile(filename) == False:
            self._raise_exception('Invalid file: ' + filename)

        self.OLE = OLEFile(filename)

        self.ole_logger.debug('***** Parse Word Document *****')
        self.FIB = FIB(self.OLE.find_object_by_name('WordDocument'))

        for i in range(0, len(self.OLE.Directory)):
            if self.OLE.Directory[i].Name == '\x05DocumentSummaryInformation':
                self.DocumentSummaryInfo = DocSummaryInfo(self.OLE.find_object_by_index(i))
            

if __name__ == '__main__':

    init_logging(True)
    
    try:
        docfile = DOCFile('oletest.doc')
    except Exception as e:
        print e
    