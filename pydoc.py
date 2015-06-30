# A simple DOC file parser based on pyole

import os
import struct
import logging
import datetime
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
        #if self.unused != 0:
        #    self.ole_logger.warning('DOC.FIB.FIBBase.unused is not zero.')

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


class FibRgFcLcb(OLEBase):

    fcSttbfAssoc  = 0
    lcbSttbfAssoc  = 0
    fcSttbfRMark  = 0
    lcbSttbfRMark = 0
    fcSttbSavedBy = 0
    lcbSttbSavedBy = 0
    dwLowDateTime = 0
    dwHighDateTime  = 0

    def __init__(self, data):

        self.fcSttbfAssoc  = 0
        self.lcbSttbfAssoc  = 0
        self.fcSttbfRMark  = 0
        self.lcbSttbfRMark = 0
        self.fcSttbSavedBy = 0
        self.lcbSttbSavedBy = 0
        self.dwLowDateTime = 0
        self.dwHighDateTime = 0

        self.fcSttbfAssoc = struct.unpack('<I', data[0x100:0x104])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.fcSttbfAssoc: ' + str(hex(self.fcSttbfAssoc)))
        self.lcbSttbfAssoc = struct.unpack('<I', data[0x104:0x108])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.lcbSttbfAssoc: ' + str(hex(self.lcbSttbfAssoc)))

        self.fcSttbfRMark = struct.unpack('<I', data[0x198:0x19C])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.fcSttbfRMark: ' + str(hex(self.fcSttbfRMark)))
        self.lcbSttbfRMark = struct.unpack('<I', data[0x19C:0x1A0])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.lcbSttbfRMark: ' + str(hex(self.lcbSttbfRMark)))

        self.fcSttbSavedBy = struct.unpack('<I', data[0x238:0x23C])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.fcSttbSavedBy: ' + str(hex(self.fcSttbSavedBy)))
        self.lcbSttbSavedBy = struct.unpack('<I', data[0x23C:0x240])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.lcbSttbSavedBy: ' + str(hex(self.lcbSttbSavedBy)))

        self.dwLowDateTime = struct.unpack('<I', data[0x2B8:0x2BC])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.dwLowDateTime: ' + str(hex(self.dwLowDateTime)))
        self.dwHighDateTime = struct.unpack('<I', data[0x2BC:0x2C0])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.dwHighDateTime: ' + str(hex(self.dwHighDateTime)))


class FIB(OLEBase):

    FIBBase = None
    csw = 0
    fibRgW = ''
    cslw = 0
    fibRgLw = ''
    cbRgFcLcb = 0
    fibRgFcLcbBlob = ''
    cswNew = 0

    def __init__(self, data):
        
        self.FIBBase = None
        self.csw = 0
        self.fibRgW = ''
        self.cslw = 0
        self.fibRgLw = ''
        self.cbRgFcLcb = 0
        self.fibRgFcLcbBlob = ''
        self.cswNew = 0

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

        self.fibRgFcLcbBlob = FibRgFcLcb(data[0x9A:0x9A+self.cbRgFcLcb*8])

        self.cswNew = struct.unpack('<H', data[0x9A+self.cbRgFcLcb*8:0x9A+self.cbRgFcLcb*8+0x02])[0]
        self.ole_logger.debug('DOC.FIB.cswNew: ' + str(hex(self.cswNew)))


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
        
        PIDSI = {'PIDSI_CODEPAGE':0x01, 'PIDSI_TITLE':0x02, 'PIDSI_SUBJECT':0x03, 'PIDSI_AUTHOR':0x04, 'PIDSI_KEYWORDS':0x05,
              'PIDSI_COMMENTS':0x06, 'PIDSI_TEMPLATE':0x07, 'PIDSI_LASTAUTHOR':0x08, 'PIDSI_REVNUMBER':0x09, 'PIDSI_EDITTIME':0x0A,
              'PIDSI_LASTPRINTED':0x0B, 'PIDSI_CREATE_DTM':0x0C, 'PIDSI_LASTSAVE_DTM':0x0D, 'PIDSI_PAGECOUNT':0x0E, 'PIDSI_WORDCOUNT':0x0F,
              'PIDSI_CHARCOUNT':0x10, 'PIDSI_APPNAME':0x12, 'PIDSI_DOC_SECURITY':0x13}

        PropertyType= {'VT_EMPTY':0x00, 'VT_NULL':0x01, 'VT_I2':0x02, 'VT_I4':0x03, 'VT_R4':0x04, 'VT_R8':0x05, 'VT_CY':0x06, 'VT_DATE': 0x07, 'VT_BSTR':0x08,
                       'VT_ERROR':0x0A, 'VT_BOOL':0x0B, 'VT_VARIANT':0x0C, 'VT_DECIMAL':0x0E, 'VT_I1':0x10, 'VT_UI1':0x11, 'VT_UI2':0x12, 'VT_UI4':0x13, 'VT_I8':0x14, 'VT_UI8':0x15,
                       'VT_INT':0x16, 'VT_UINT':0x17, 'VT_LPSTR':0x1E, 'VT_LPWSTR':0x1F, 'VT_FILETIME':0x40, 'VT_BLOB':0x41, 'VT_STREAM':0x42, 'VT_STORAGE':0x43,
                       'VT_STREAMED_Object':0x44, 'VT_STORED_Object':0x45, 'VT_BLOB_Object':0x46, 'VT_CF':0x47, 'VT_CLSID':0x48, 'VT_VERSIONED_STREAM':0x49,
                       'VT_VECTOR':0x1000, 'VT_ARRAY':0x2000}

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

    def _filetime_to_datetime(self, microseconds):
        seconds, microseconds = divmod(microseconds/10, 1000000)
        days, seconds = divmod(seconds, 86400)
        time = datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(days, seconds, microseconds)
        return str(time)


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


class DOCFile(OLEBase):

    OLE = None
    FIB = None
    SummaryInfo = None
    DocumentSummaryInfo = None

    def __init__(self, filename):
        self.OLE = None
        self.FIB = None
        self.SummaryInfo = None
        self.DocumentSummaryInfo = None

        if os.path.isfile(filename) == False:
            self._raise_exception('Invalid file: ' + filename)

        self.OLE = OLEFile(filename)

        self.ole_logger.debug('***** Parse Word Document *****')
        self.FIB = FIB(self.OLE.find_object_by_name('WordDocument'))

        for i in range(0, len(self.OLE.Directory)):
            if self.OLE.Directory[i].Name == '\x05SummaryInformation':
                self.SummaryInfo = SummaryInfo(self.OLE.find_object_by_index(i))

            if self.OLE.Directory[i].Name == '\x05DocumentSummaryInformation':
                self.DocumentSummaryInfo = DocSummaryInfo(self.OLE.find_object_by_index(i))

    def show_rmark_authors(self):
        if self.FIB.fibRgFcLcbBlob.fcSttbfRMark != 0:
            table_stream = ''
            if self.FIB.FIBBase.fWhichTblStm == 1:
                table_stream = self.OLE.find_object_by_name('1Table')
            elif self.FIB.FIBBase.fWhichTblStm == 1:
                table_stream = self.OLE.find_object_by_name('0Table')
            else:
                print 'DOC.FIB.FIBBase.fWhichTblStm has an abnormal value.'
                return
                
            if len(table_stream) > 0:
                #print table_stream
                offset = self.FIB.fibRgFcLcbBlob.fcSttbfRMark
                length = self.FIB.fibRgFcLcbBlob.lcbSttbfRMark
                SttbfRMark = table_stream[offset:offset+length]
                fExtend = struct.unpack('<H', SttbfRMark[0x00:0x02])[0]
                if fExtend != 0xFFFF:
                    print 'fExtend has an abnormal value.'
                    return
                cbExtra = struct.unpack('<H', SttbfRMark[0x04:0x06])[0]
                if cbExtra != 0:
                    print 'cbExtra has an abnormal value.'
                    return
                cData = struct.unpack('<H', SttbfRMark[0x02:0x04])[0]
                offset = 0
                for i in range(0, cData):
                    cchData = struct.unpack('<H', SttbfRMark[0x06+offset:0x08+offset])[0]
                    Data = SttbfRMark[0x06+offset+0x02:0x08+offset+cchData*2]
                    print Data.decode('utf-16')
                    offset = offset + 0x02 + cchData*2
            else:
                print 'Failed to read the Table Stream.'
        else:
            print 'No revision marks or comments author information.'
            

if __name__ == '__main__':

    init_logging(True)
    
    try:
        docfile = DOCFile('oletest.doc')
        docfile.show_rmark_authors()
    except Exception as e:
        print e
    