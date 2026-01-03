import webview
import os
import sys
import json
import time
import threading
import ctypes
from datetime import datetime, timedelta
import subprocess
import psutil
import requests
import re
import itertools
import collections
import struct
import tempfile
from platform import architecture
from threading import Thread

# Check for admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

# =============== START OF EXACT BACKEND CODE ===============

# Constants
STANDARD_INFORMATION = b'\x10\x00\x00\x00'
ATTRIBUTE_LIST = b'\x20\x00\x00\x00'
FILE_NAME = b'\x30\x00\x00\x00'
OBJECT_ID = b'\x40\x00\x00\x00'
SECURITY_DESCRIPTOR = b'\x50\x00\x00\x00'
VOLUME_NAME = b'\x60\x00\x00\x00'
VOLUME_INFORMATION = b'\x70\x00\x00\x00'
DATA = b'\x80\x00\x00\x00'
INDEX_ROOT = b'\x90\x00\x00\x00'
INDEX_ALLOCATION = b'\xA0\x00\x00\x00'
BITMAP = b'\xB0\x00\x00\x00'
REPARSE_POINT = b'\xC0\x00\x00\x00'
EA_INFORMATION = b'\xD0\x00\x00\x00'
EA = b'\xE0\x00\x00\x00'
PROPERTY_SET = b'\xF0\x00\x00\x00'
LOGGED_UTILITY_STREAM = b'\x00\x01\x00\x00'
ATTRIBUTE_END_MARKER = b'\xFF\xFF\xFF\xFF'

# USN Reason flags
USN_REASONS = collections.OrderedDict([
    (0x1, 'DATA_OVERWRITE'),
    (0x2, 'DATA_EXTEND'),
    (0x4, 'DATA_TRUNCATION'),
    (0x10, 'NAMED_DATA_OVERWRITE'),
    (0x20, 'NAMED_DATA_EXTEND'),
    (0x40, 'NAMED_DATA_TRUNCATION'),
    (0x100, 'FILE_CREATE'),
    (0x200, 'FILE_DELETE'),
    (0x400, 'EA_CHANGE'),
    (0x800, 'SECURITY_CHANGE'),
    (0x1000, 'RENAME_OLD_NAME'),
    (0x2000, 'RENAME_NEW_NAME'),
    (0x4000, 'INDEXABLE_CHANGE'),
    (0x8000, 'BASIC_INFO_CHANGE'),
    (0x10000, 'HARD_LINK_CHANGE'),
    (0x20000, 'COMPRESSION_CHANGE'),
    (0x40000, 'ENCRYPTION_CHANGE'),
    (0x80000, 'OBJECT_ID_CHANGE'),
    (0x100000, 'REPARSE_POINT_CHANGE'),
    (0x200000, 'STREAM_CHANGE'),
    (0x80000000, 'CLOSE')
])

# Common executable/script extensions
executable_extensions = {
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.scr', '.com', 
    '.ps1', '.psm1', '.psd1', '.psc1', '.pssc', '.ps1xml', '.cdxml', '.psrc', 
    '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', 
    '.msi', '.msp', '.mst', '.msc', '.msh', '.msh1', '.msh2', '.mshxml', 
    '.py', '.pyc', '.pyo', '.pyw', '.pyz', '.pyzw', 
    '.jar', '.class', '.war', '.ear', 
    '.reg', '.inf', '.pif', '.scf', '.shs', '.shb', 
    '.lnk', '.url', '.hta', '.isp', '.ispc', '.application', 
    '.gadget', '.mspx', '.xaml', '.xbap', 
    '.app', '.appref-ms', '.ade', '.adp', '.bas', '.chm', 
    '.crt', '.csh', '.der', '.fxp', '.hlp', '.hpj', '.hta', 
    '.ins', '.isp', '.its', '.js', '.jse', '.ksh', '.mad', 
    '.maf', '.mag', '.mam', '.maq', '.mar', '.mas', '.mat', 
    '.mau', '.mav', '.maw', '.mda', '.mdb', '.mde', '.mdt', 
    '.mdw', '.mdz', '.msc', '.msh', '.msh1', '.msh2', '.mshxml', 
    '.msi', '.msp', '.mst', '.ops', '.pcd', '.pif', '.pl', 
    '.plg', '.prf', '.prg', '.pst', '.reg', '.scf', '.scr', 
    '.sct', '.shb', '.shs', '.url', '.txt', '.csv', '.rc', '.cs', '.zip',
    '.rar', '.meta', '.rpf'
}

actual_executable_extensions = {
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.scr', '.com',
    '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.wsh', '.msi', '.msp', '.py', '.jar', '.reg'
}

# Classes from your code
class DataRun:
    def __init__(self, header, length, offset):
        self.header = header
        self.length = length
        self.offset = offset

class RawOffset:
    def __init__(self, offset, bytes_acc, bytes_per_run, sectors_per_run):
        self.offset = offset
        self.bytes_acc = bytes_acc
        self.bytes_per_run = bytes_per_run
        self.sectors_per_run = sectors_per_run

class BootSector:
    def __init__(self, buffer):
        self.align = buffer[0]
        self.jump = buffer[0:3]
        self.SystemName = buffer[3:11]
        self.BytesPerSector = int.from_bytes(buffer[11:13], byteorder="little")
        self.sectors_per_cluster = int.from_bytes(buffer[13:14], byteorder="little")
        self.ReservedSectors = int.from_bytes(buffer[14:16], byteorder="little")
        self.MediaDescriptor = int.from_bytes(buffer[21:22], byteorder="little")
        self.SectorsPerTrack = int.from_bytes(buffer[24:26], byteorder="little")
        self.NumberOfHeads = int.from_bytes(buffer[26:28], byteorder="little")
        self.HiddenSectors = int.from_bytes(buffer[28:32], byteorder="little")
        self.TotalSectors = int.from_bytes(buffer[40:48], byteorder="little")
        self.LogicalClusterNumberforthefileMFT = int.from_bytes(buffer[48:56], byteorder="little")
        self.LogicalClusterNumberforthefileMFTMirr = int.from_bytes(buffer[56:64], byteorder="little")
        self.ClustersPerFileRecordSegment = int.from_bytes(buffer[64:68], byteorder="little")
        self.ClustersPerIndexBlock = int.from_bytes(buffer[68:72], byteorder="little")
        self.NTFSVolumeSerialNumber = int.from_bytes(buffer[72:80], byteorder="little")
        self.Checksum = int.from_bytes(buffer[80:82], byteorder="little")

class NtfsAttributes:
    def __init__(self):
        self.standard_information = None
        self.attribute_list = None
        self.file_name = None
        self.object_id = None
        self.security_descriptor = None
        self.volume_name = None
        self.volume_information = None
        self.data = None
        self.index_root = None
        self.index_allocation = None
        self.bitmap = None
        self.reparse_point = None
        self.ea_information = None
        self.ea = None
        self.property_set = None
        self.logged_utility_stream = None
        self.attribute_end_marker = None

class Indx:
    def __init__(self):
        self.indx_entry_number = None
        self.indx_mft_ref = None
        self.indx_file_name = None

# Helper functions from your code
def swap(data):
    return "".join([data[i: i + 2] for i in range(0, len(data), 2)][::-1])

def extract_boot_sector(handle):
    data = handle.read(512)
    boot_sector = BootSector(data)
    bytes_per_cluster = boot_sector.BytesPerSector * boot_sector.sectors_per_cluster
    mft_offset = bytes_per_cluster * boot_sector.LogicalClusterNumberforthefileMFT
    if boot_sector.ClustersPerFileRecordSegment > 127:
        mft_record_size = 2 ** (256 - boot_sector.ClustersPerFileRecordSegment)
    else:
        mft_record_size = bytes_per_cluster * boot_sector.ClustersPerFileRecordSegment

    return bytes_per_cluster, mft_offset, mft_record_size, boot_sector.sectors_per_cluster

def get_last_offset(runs):
    if runs:
        counter = 0
        while counter < len(runs) and int(runs[-counter].offset, 16) == 0:
            counter += 1
        if runs[-counter].offset != 0:
            return runs[-counter].offset
        else:
            return "0"
    else:
        return "0"

def parse_data_run(data_run):
    i = 0
    runs = []
    r = 0
    base = 0
    data_run = "".join(['0x{0:0{1}X}'.format(ord(data_run[i:i + 1]), 2)[2:] for i in range(len(data_run))])
    while i < len(data_run):
        header = data_run[i:i + 2]
        if header != "00":
            length = swap(data_run[i + 2:i + 2 + int(header[1], 16) * 2])
            if not length:
                length = "0"
            length = "0x{}".format(length)
            offset_string = swap(
                data_run[i + 2 + int(header[1], 16) * 2:i + 2 + int(header[1], 16) * 2 + int(header[0], 16) * 2])
            if offset_string:
                add_to_offset = int(offset_string, 16) - ((r > 1) and int(offset_string[0], 16) > 7) * int(
                    "10000000000000000"[:int(header[0], 16) * 2 + 1], 16)
                base += add_to_offset
                offset = hex(base)

                offset_data = offset if offset else "0x0"
            else:
                offset_data = "0x0"
            if int(length, 16) > 16 and int(length, 16) % 16 > 0:
                runs.append(DataRun(header, int(length, 16) - int(length, 16) % 16, int(offset_data, 16)))
                offset_data = hex(int(offset_data, 16) + runs[-1].length)
                length = hex(int(length, 16) % 16)
            runs.append(DataRun(header, int(length, 16), int(offset_data, 16)))
        else:
            break
        i = i + 2 + int(header[1], 16) * 2 + int(header[0], 16) * 2
        r += 1
    return runs

def get_raw_offset(handle, parsed, real_size, bytes_per_cluster, raw_entry=None):
    header_name = ""

    if raw_entry:
        header_relative_len = int.from_bytes(raw_entry[9:10], "little")
        header_relative_offset = int.from_bytes(raw_entry[10:12], byteorder="little")
        if header_relative_len > 0:
            header_name = "".join([chr(i) for i in raw_entry[
                                                   header_relative_offset: header_relative_offset + header_relative_len * 2].replace(
                b"\x00", b"")])

    raw_offsets = []
    bytes_acc = 0
    core_attribute = b""
    for run in parsed:
        if run.offset == 0:
            offset = 0
            bytes_acc = bytes_per_cluster * run.length
            real_size -= bytes_per_cluster * run.length
            raw_offsets.append(RawOffset(offset, bytes_acc, 0, 0))
            bytes_acc = 0
            continue

        offset = run.offset * bytes_per_cluster
        handle.seek(offset)
        g = run.length
        while g > 16 and real_size > bytes_per_cluster * 16:
            bytes_acc += bytes_per_cluster * 16
            data = handle.read(bytes_per_cluster * 16)
            core_attribute += data[:bytes_per_cluster * 16]
            g -= 16
            real_size -= bytes_per_cluster * 16

        if g != 0:
            data = handle.read(bytes_per_cluster * 16)
            if real_size > bytes_per_cluster * g:
                core_attribute += data[:bytes_per_cluster * g]
                bytes_acc += bytes_per_cluster * g
                real_size -= bytes_per_cluster * g
            else:
                core_attribute += data[:real_size]
                bytes_acc += real_size

        if raw_offsets:
            if raw_offsets[-1].offset == 0:
                raw_offsets.append(RawOffset(offset, bytes_acc, bytes_acc, bytes_acc / 512))
            else:
                bytes_per_run = bytes_acc - raw_offsets[-1].bytes_acc
                raw_offsets.append(RawOffset(offset, bytes_acc, bytes_per_run, bytes_per_run / 512))

    return raw_offsets, core_attribute, header_name

def get_attributes(entry):
    nfts_attributes = NtfsAttributes()
    attribute_offset = int.from_bytes(entry[20:21], byteorder="little")
    while True:
        attribute_type = entry[attribute_offset:attribute_offset + 4]
        attribute_size = int.from_bytes(entry[attribute_offset + 4:attribute_offset + 8], byteorder="little")
        if attribute_type == ATTRIBUTE_LIST:
            nfts_attributes.attribute_list = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == FILE_NAME:
            nfts_attributes.file_name = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == DATA:
            if not nfts_attributes.data:
                nfts_attributes.data = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == INDEX_ROOT:
            nfts_attributes.index_root = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == INDEX_ALLOCATION:
            nfts_attributes.index_allocation = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == ATTRIBUTE_END_MARKER:
            break
        attribute_offset += attribute_size

    return nfts_attributes

def parse_mft_record(mft_entry):
    attribute_offset = int(hex(ord(mft_entry[20:21])), 16)
    attribute_type = 0
    while attribute_type < 256:
        attribute_type = int.from_bytes(mft_entry[attribute_offset:attribute_offset + 4], byteorder="little")
        attribute_size = int.from_bytes(mft_entry[attribute_offset + 4: attribute_offset + 8], byteorder="little")
        if attribute_type == 128:
            datarun = decode_attribute(mft_entry[attribute_offset:attribute_offset + attribute_size])
            return datarun
        else:
            attribute_offset += attribute_size

def decode_index_entries(data_run):
    entries = []
    next_entry_offset = 0
    while next_entry_offset + 16 < len(data_run):
        index = Indx()
        mft_ref = int.from_bytes(data_run[next_entry_offset:next_entry_offset + 6], byteorder="little")
        index.indx_mft_ref = mft_ref
        flags = int.from_bytes(data_run[next_entry_offset + 11: next_entry_offset + 13], byteorder="little")

        indx_filename_length = int.from_bytes(data_run[next_entry_offset + 80:next_entry_offset + 81],
                                              byteorder="little")
        data = data_run[next_entry_offset + 82: next_entry_offset + 82 + indx_filename_length * 2]
        index_filename = "".join([chr(i) for i in data.replace(b"\x00", b"")])
        index.indx_file_name = index_filename

        padding = (2 + indx_filename_length * 2) % 8
        if padding:
            padding = 8 - padding

        if flags:
            sub_node_offset_length = 8
        else:
            sub_node_offset_length = 0
        index.indx_entry_number = 0
        entries.append(index)

        next_entry_offset += 82 + indx_filename_length * 2 + padding + sub_node_offset_length

    return entries

def get_ref(name, indx_entries):
    for entry in indx_entries:
        if entry.indx_file_name == name:
            return entry.indx_mft_ref

def get_index_entries(entry):
    index_entry = entry[32:]
    return decode_index_entries(index_entry)

def strip_mft_record(record):
    record = update_record(record)
    record_size = int.from_bytes(record[24:28], byteorder="little")
    header_size = int.from_bytes(record[20:22], byteorder="little")
    return record[header_size:record_size - 8]

def strip_index(index):
    record_size = int.from_bytes(index[28:30], byteorder="little")
    header_size = int.from_bytes(index[24:28], byteorder="little")
    is_not_leaf_node = index[36:37]
    entry = index[24 + header_size:24 + header_size + record_size - header_size - 16]
    if is_not_leaf_node == b"\x01":
        entry = entry[:-16]

    return entry

def get_index_alloc_entries(entry):
    next_position = 0
    total_indx_entries = b""
    while next_position < len(entry) + 32:
        header = "".join([chr(i) for i in entry[next_position: next_position + 4]])
        if header != "INDX":
            next_position += 4096
            continue
        indx_entries = strip_index(entry[next_position: next_position + 4096])
        total_indx_entries += indx_entries
        next_position += 4096

    return decode_index_entries(total_indx_entries)

def decode_attribute(attr):
    resident = attr[8]
    if resident:
        offset = int.from_bytes(attr[32:34], byteorder="little")
        datarun = attr[offset:]
    else:
        offset = int.from_bytes(attr[20:22], byteorder="little")
        datarun = attr[offset:]

    return datarun

def find_file_MFT_record(handle, target_file, parsed_data_run, mft_record_size, sectors_per_cluster, bytes_per_cluster):
    counter = 0
    final = 0
    jump = 0
    records_divisor = mft_record_size / 512
    records_in_run = -1
    run = None
    for run in parsed_data_run:
        records_in_run = run.length * sectors_per_cluster / records_divisor
        counter += records_in_run
        if counter > target_file:
            break

    if records_in_run < 0 or not run:
        return


    base = counter - records_in_run
    records_per_cluster = sectors_per_cluster / records_divisor

    while final < target_file:
        jump += records_per_cluster
        final = base + jump


    records_too_much = final - target_file
    location = run.offset * bytes_per_cluster + jump / records_per_cluster * bytes_per_cluster - records_too_much * mft_record_size
    handle.seek(int(location))
    record = handle.read(mft_record_size)

    if int.from_bytes(record[44:48], byteorder="little") == target_file:
        return location, record
    else:
        return

def get_core_attribute(handle, record, real_size, parsed_datarun, index, bytes_per_cluster):
    entries = []
    result = get_raw_offset(handle, parsed_datarun, real_size, bytes_per_cluster, record)
    if result:
        raw, core_attribute, header_name = result
        if header_name == "$I30":
            if index == INDEX_ROOT:
                entries = get_index_entries(core_attribute)
            elif index == INDEX_ALLOCATION:
                entries = get_index_alloc_entries(core_attribute)

    return entries

def update_record(record):
    offset = int.from_bytes(record[4:6], byteorder="little")
    size = int.from_bytes(record[6:8], byteorder="little")
    data = record[offset: offset + size * 2]

    return record[0:510] + data[2:4] + record[512:1022] + data[4:6]

def resolve(handle, path, data_run, mft_record_size, sectors_per_cluster, bytes_per_cluster):
    resolved = None
    next_ref = 5
    splitted = path.split("\\")
    if len(splitted) > 2:
        for i in range(len(splitted[2:])):
            part = splitted[i + 1]
            result = find_file_MFT_record(handle, next_ref, data_run, mft_record_size, sectors_per_cluster,
                                          bytes_per_cluster)
            if not result:
                print("parsing error")
                exit(0)
            location, record = result
            record = update_record(record)

            ntfs_attributes = get_attributes(record)
            record_data_run = decode_attribute(ntfs_attributes.index_allocation)
            parsed_data_run = parse_data_run(record_data_run)

            record_size = int.from_bytes(ntfs_attributes.index_allocation[48:48 + 8], "little")

            indx_entries = get_core_attribute(handle, ntfs_attributes.index_allocation, record_size, parsed_data_run,
                                              INDEX_ALLOCATION, bytes_per_cluster)

            next_ref = get_ref(part, indx_entries)
            if i == len(splitted[2:]) - 1:
                result = find_file_MFT_record(handle, next_ref, data_run, mft_record_size, sectors_per_cluster,
                                              bytes_per_cluster)
                if result:
                    location, record = result
                    record = update_record(record)
                    ntfs_attributes = get_attributes(record)
                    indx_entries = get_index_entries(ntfs_attributes.index_root[32:])

                resolved = get_ref(splitted[-1], indx_entries)

    return resolved

def get_refs(attr_list, current_ref):
    refs = []
    offset = 0
    while len(attr_list) > offset:
        ref = int.from_bytes(attr_list[offset + 16:offset + 20], byteorder="little")
        if ref != current_ref:
            refs.append(ref)
        offset += int.from_bytes(attr_list[offset + 4: offset + 6], byteorder="little")

    return refs

def get_total_clusters(entry):
    start_offset = int.from_bytes(entry[16:24], byteorder="little")
    last_offset = int.from_bytes(entry[24:32], byteorder="little")
    total_clusters = last_offset - start_offset
    return total_clusters

def parse_attribute_list(attribute_list, usn_ref, handle, mft_data_run, mft_record_size, sectors_per_cluster,
                         bytes_per_cluster):
    raw_offsets = []
    list_offset = int.from_bytes(attribute_list[20:22], byteorder="little")
    a_list = attribute_list[list_offset:]
    refs = get_refs(a_list, usn_ref)
    prev_size = 0
    prev_total_clusters = 0
    for tmp_ref in refs:
        result = find_file_MFT_record(handle, tmp_ref, mft_data_run, mft_record_size, sectors_per_cluster,
                                      bytes_per_cluster)
        if not result:
            print("Something went wrong")
            continue
        location, record = result
        attr = strip_mft_record(record)
        offset = int.from_bytes(attr[32:34], byteorder="little")
        record_data_run = attr[offset:]
        attr_size = int.from_bytes(attr[48:48 + 8], byteorder="little")
        total_clusters = get_total_clusters(attr)
        if not attr_size:
            total_clusters = prev_total_clusters
            attr_size = prev_size - total_clusters * bytes_per_cluster
        prev_size = attr_size
        prev_total_clusters = total_clusters
        parsed = parse_data_run(record_data_run)
        raw_offsets, core_attribute, header_name = get_raw_offset(handle, parsed, attr_size, bytes_per_cluster, attr)

    return raw_offsets

def parse_attribute_data(handle, data, bytes_per_cluster):
    offset = int.from_bytes(data[32:34], byteorder="little")
    record_data_run = data[offset:]

    usn_size = int.from_bytes(data[48:48 + 8], byteorder="little")

    parsed = parse_data_run(record_data_run)
    raw_offsets, core_attribute, header_name = get_raw_offset(handle, parsed, usn_size, bytes_per_cluster)

    return raw_offsets

def dump_to_file(handle, raw_offsets, dest):
    with open(dest, "wb") as output:
        for raw_offset in raw_offsets[1:]:
            handle.seek(raw_offset.offset)
            data = handle.read(raw_offset.bytes_per_run)
            written = output.write(data)

# =============== END OF EXACT BACKEND CODE ===============

class DREParser:
    def __init__(self):
        self.is_scanning = False
        self.results = {}
        self.start_time = None
        self.done = False
        self.output_path = None
        
        # Global variables from original code
        self.DeletedFiles = []
        self.RenamedFiles = []
        self.ReplacedFiles = []
        self.ExecutedFiles = []
        self.RecycleBin = []
        self.RecycleBin_files = []
        self.RecycleBin_mdate = "No Recycle Bin found"
        self.FilteredDeletedFiles = []
        self.FilteredRenamedFiles = []
        self.FilteredReplacedFiles = []
        self.Results = []
        
        # Patterns from original code
        self.patron = re.compile(r'(?:^[A-Za-z]:[\\/]|^file:///)(?:[^\\/:]+[\\/])*[^\\/:\s]+\.[A-Za-z0-9]{1,10}(?=\s|$|"|\')')
        self.patron3 = re.compile(r'\$R[a-zA-Z0-9]{6}\.')
        self.patron4 = re.compile(r'S\-.*')
        
        # USN Parsing functions from original code
        self.REASONS_LIST = ['RENAME_OLD_NAME', 'FILE_DELETE', 'RENAME_NEW_NAME', 
                            'RENAME_OLD_NAME CLOSE', 'FILE_DELETE CLOSE', 'RENAME_NEW_NAME CLOSE']
    
    def filetimeToHumanReadable(self, filetime):
        try:
            return str(datetime.fromtimestamp((float(filetime) * 1e-7 - 11644473600)).strftime("%d/%m/%Y %H:%M:%S"))
        except:
            return "N/A"
    
    def convertAttributes(self, attributeType, data):
        attributeList = [attributeType[i] for i in attributeType if i & data]
        return ' '.join(attributeList)
    
    def parseUsn(self, infile, usn):
        recordProperties = [
            'majorVersion',
            'minorVersion',
            'fileReferenceNumber',
            'parentFileReferenceNumber',
            'usn',
            'timestamp',
            'reason',
            'sourceInfo',
            'securityId',
            'fileAttributes',
            'filenameLength',
            'filenameOffset'
        ]
        recordDict = dict(zip(recordProperties, usn))
        recordDict['reason'] = self.convertAttributes(USN_REASONS, recordDict['reason'])
        if not recordDict['reason'] in self.REASONS_LIST:
            return None
        recordDict['humanTimestamp'] = self.filetimeToHumanReadable(recordDict['timestamp'])
        recordDict['filename'] = self.filenameHandler(infile, recordDict)
        
        filename_lower = recordDict['filename'].lower()
        has_executable_ext = any(filename_lower.endswith(ext) for ext in executable_extensions)
        
        if not has_executable_ext:
            return None
            
        if recordDict['reason'] == "FILE_DELETE CLOSE":
            self.DeletedFiles.append(
                recordDict['filename'] + ":::" + recordDict['humanTimestamp']
            )
        elif recordDict['reason'] == 'RENAME_OLD_NAME':
            self.RenamedFiles.append(
                recordDict['filename'] + ":::" + str(recordDict['fileReferenceNumber'])
            )
        elif recordDict['reason'] == 'RENAME_NEW_NAME CLOSE':
            self.FindProgramID(str(recordDict['fileReferenceNumber']), recordDict['filename'], recordDict['humanTimestamp'])

        return recordDict
    
    def FindProgramID(self, programid, filename, humantime):
        for item in self.RenamedFiles:
            if item.split(":::")[1] == programid and item.split(":::")[0] != filename:
                if any(filename.lower().endswith(ext) for ext in executable_extensions):
                    self.RenamedFiles[self.RenamedFiles.index(item)] = item.split(":::")[0] + ":::" + filename + ":::" + humantime
            elif item.split(":::")[1] == programid and item.split(":::")[0] == filename:
                if any(filename.lower().endswith(ext) for ext in executable_extensions):
                    self.ReplacedFiles.append(filename + ":::" + humantime)
                    self.RenamedFiles.remove(item)
    
    def findFirstRecord(self, infile):
        while True:
            data = infile.read(65536).lstrip(b'\x00')
            if data:
                return infile.tell() - len(data)
    
    def findNextRecord(self, infile, journalSize):
        while True:
            try:
                recordLength = struct.unpack_from('<I', infile.read(4))[0]
                if recordLength:
                    infile.seek(-4, 1)
                    return infile.tell() + recordLength
            except struct.error:
                if infile.tell() >= journalSize:
                    return False
    
    def filenameHandler(self, infile, recordDict):
        try:
            filename = struct.unpack_from('<{}s'.format(
                recordDict['filenameLength']),
                infile.read(recordDict['filenameLength']))[0]
            return filename.decode('utf16')
        except(UnicodeDecodeError, struct.error, IndexError):
            return ''
    
    def USNDump(self):
        self.output_path = tempfile.gettempdir() + "\\usn.bin"
        target_file = r"C:\$Extend\$UsnJrnl"

        try:
            handle = open(r"\\.\c:", "rb")
        except:
            raise Exception("[!] Failed to get handle to the physical partition, are you running with administrative privileges?")

        bytes_per_cluster, mft_offset, mft_record_size, sectors_per_cluster = extract_boot_sector(handle)

        handle.seek(mft_offset)
        mft_record = handle.read(mft_record_size)
        if mft_record[22:24] != b"\x01\x00" or int.from_bytes(mft_record[44:48], byteorder='little', signed=False) != 0:
            raise Exception("Couldn't find the MFT record")

        mft_data_run_data = parse_mft_record(mft_record)
        mft_data_run = parse_data_run(mft_data_run_data)
        ref = resolve(handle, target_file, mft_data_run, mft_record_size, sectors_per_cluster, bytes_per_cluster)

        offset, record = find_file_MFT_record(handle, ref, mft_data_run, mft_record_size, sectors_per_cluster,
                                              bytes_per_cluster)
        record = update_record(record)

        ntfs_attributes = get_attributes(record)
        if ntfs_attributes.attribute_list:
            raw_offsets = parse_attribute_list(ntfs_attributes.attribute_list, ref, handle, mft_data_run, mft_record_size,
                                               sectors_per_cluster, bytes_per_cluster)
        else:
            raw_offsets = parse_attribute_data(handle, ntfs_attributes.data, bytes_per_cluster)

        dump_to_file(handle, raw_offsets, self.output_path)
        handle.close()
        
        return self.output_path
    
    def USNParse(self):
        self.ReplacedFiles = []
        self.RenamedFiles = []
        self.DeletedFiles = []
        FinalRenamedFiles = []
        
        if not self.output_path or not os.path.exists(self.output_path):
            return None
            
        journalSize = os.path.getsize(self.output_path)
        if os.stat(self.output_path).st_size < 2:
            return None

        with open(self.output_path, 'rb') as i:
            i.seek(self.findFirstRecord(i))
            
            while True:
                nextRecord = self.findNextRecord(i, journalSize)
                if nextRecord == False:
                    break
                recordLength = struct.unpack_from('<I', i.read(4))[0]
                recordData = struct.unpack_from('<2H4Q4I2H', i.read(56))
                u = self.parseUsn(i, recordData)
                if u == None:
                    i.seek(nextRecord)
                i.seek(nextRecord)
        
        # Clean up temp file
        try:
            os.remove(self.output_path)
        except:
            pass
            
        for item in self.ReplacedFiles:
            if len(item.split(":::")) == 2:
                self.ReplacedFiles.remove(item)
                
        for item in self.RenamedFiles:
            if len(item.split(":::")) != 2:
                FinalRenamedFiles.append(item)
        
        return self.DeletedFiles, FinalRenamedFiles, self.ReplacedFiles
    
    def download_xxstrings(self):
        temp_dir = tempfile.gettempdir()
        xxstrings_path = os.path.join(temp_dir, 'xxstrings.exe')
        
        if not os.path.exists(xxstrings_path):
            try:
                if '64bit' in architecture():
                    url = 'https://github.com/ZaikoARG/xxstrings/releases/download/1.0.0/xxstrings64.exe'
                else:
                    url = 'https://github.com/ZaikoARG/xxstrings/releases/download/1.0.0/xxstrings.exe'
                
                r = requests.get(url, timeout=30)
                with open(xxstrings_path, 'wb') as f:
                    f.write(r.content)
            except Exception as e:
                print(f"Failed to download xxstrings: {e}")
        
        return xxstrings_path
    
    def explorerdump(self):
        xxstrings_path = self.download_xxstrings()
        pid = None
        
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == 'explorer.exe':
                pid = proc.info['pid']
                break
        
        if pid and os.path.exists(xxstrings_path):
            try:
                explorerstrings = subprocess.check_output(
                    f'"{xxstrings_path}" -p {pid}', 
                    shell=True,
                    stderr=subprocess.STDOUT,
                    timeout=60
                )
                
                # Parse the output
                for linea in explorerstrings.decode('utf-8', errors='ignore').splitlines():
                    bebeto = self.patron.search(linea)
                    if bebeto != None:
                        full_path = bebeto.group(0)
                        cleaned_path = full_path.replace("file:///", "").replace("%20", " ")
                        cleaned_path = cleaned_path.replace("/", "\\")
                        filename = os.path.basename(cleaned_path)
                        
                        if any(filename.lower().endswith(ext) for ext in actual_executable_extensions):
                            self.ExecutedFiles.append(filename)
                
                # Remove duplicates while preserving order
                self.ExecutedFiles = list(dict.fromkeys(self.ExecutedFiles))
                
            except subprocess.CalledProcessError as grepexc:
                print(f"error code {grepexc.returncode}, {grepexc.output}")
            except subprocess.TimeoutExpired:
                print("xxstrings timed out")
            except Exception as e:
                print(f"Error in explorerdump: {e}")
    
    def scan_recycle_bin(self):
        RecycleBin_folders = []
        
        recycle_bin_path = 'C:\\$Recycle.Bin\\'
        
        if os.path.exists(recycle_bin_path):
            try:
                for file in os.listdir(recycle_bin_path):
                    if self.patron4.search(file) is not None:
                        RecycleBin_folders.append(os.path.join(recycle_bin_path, file, ''))

                if RecycleBin_folders:
                    # Get modification date from first folder
                    self.RecycleBin_mdate = datetime.fromtimestamp(
                        os.stat(RecycleBin_folders[0]).st_mtime
                    ).strftime("%d/%m/%y %H:%M:%S")
                    
                    for folder in RecycleBin_folders:
                        if os.path.exists(folder):
                            for file in os.listdir(folder):
                                if self.patron3.search(file) is not None:
                                    full_path = os.path.join(folder, file)
                                    mtime = datetime.fromtimestamp(
                                        os.stat(full_path).st_mtime
                                    ).strftime("%d/%m/%y %H:%M:%S")
                                    
                                    if any(file.lower().endswith(ext) for ext in executable_extensions):
                                        self.RecycleBin_files.append(f"{file} | {mtime}")
            except Exception as e:
                print(f"Error scanning recycle bin: {e}")
    
    def deduplicate_results(self, deleted_files, renamed_files, replaced_files, recyclebin_files, journal_recyclebin):
        """Remove duplicates where the same filename appears multiple times in the same category"""
        deduped = {
            'deletedFiles': [],
            'renamedFiles': [],
            'replacedFiles': [],
            'recycleBinFiles': [],
            'journalRecycleBin': []
        }
        
        # Track seen entries per category - use a tuple of (filename, path, entry_type)
        seen_deleted = set()
        seen_renamed = set()
        seen_replaced = set()
        seen_recyclebin = set()
        seen_journal_recyclebin = set()
        
        # Helper function to extract deduplication key
        def get_dedup_key(item, category):
            if category == 'deletedFiles':
                parts = item.split('|')
                if len(parts) >= 3:
                    # filename|path|timestamp - we ignore timestamp for deduplication
                    filename = parts[0].lower()
                    path = parts[1].lower() if len(parts) > 1 else ""
                    return f"{filename}_{path}_deleted"
            elif category == 'renamedFiles':
                parts = item.split(':::')
                if len(parts) == 3:
                    # old_name:::new_name:::timestamp
                    old_name = parts[0].lower()
                    new_name = parts[1].lower()
                    return f"{old_name}_{new_name}_renamed"
            elif category == 'replacedFiles':
                parts = item.split(':::')
                if len(parts) >= 2:
                    # filename:::timestamp
                    filename = parts[0].lower()
                    return f"{filename}_replaced"
            elif category == 'recycleBinFiles':
                # Format: "filename | timestamp"
                parts = item.split(' | ')
                if len(parts) >= 2:
                    filename = parts[0].lower()
                    return f"{filename}_recyclebin"
            elif category == 'journalRecycleBin':
                parts = item.split(':::')
                if len(parts) >= 2:
                    filename = parts[0].lower()
                    return f"{filename}_journalrecyclebin"
            return None
        
        # Process deleted files
        for item in deleted_files:
            key = get_dedup_key(item, 'deletedFiles')
            if key and key not in seen_deleted:
                seen_deleted.add(key)
                deduped['deletedFiles'].append(item)
        
        # Process renamed files
        for item in renamed_files:
            key = get_dedup_key(item, 'renamedFiles')
            if key and key not in seen_renamed:
                seen_renamed.add(key)
                deduped['renamedFiles'].append(item)
        
        # Process replaced files
        for item in replaced_files:
            key = get_dedup_key(item, 'replacedFiles')
            if key and key not in seen_replaced:
                seen_replaced.add(key)
                deduped['replacedFiles'].append(item)
        
        # Process recycle bin files
        for item in recyclebin_files:
            key = get_dedup_key(item, 'recycleBinFiles')
            if key and key not in seen_recyclebin:
                seen_recyclebin.add(key)
                deduped['recycleBinFiles'].append(item)
        
        # Process journal recycle bin
        for item in journal_recyclebin:
            key = get_dedup_key(item, 'journalRecycleBin')
            if key and key not in seen_journal_recyclebin:
                seen_journal_recyclebin.add(key)
                deduped['journalRecycleBin'].append(item)
        
        return deduped

    # Update the perform_analysis method to use deduplication
    def perform_analysis(self, window):
        self.is_scanning = True
        self.start_time = datetime.now()
        
        try:
            # Reset all variables
            self.DeletedFiles = []
            self.RenamedFiles = []
            self.ReplacedFiles = []
            self.ExecutedFiles = []
            self.RecycleBin = []
            self.RecycleBin_files = []
            self.RecycleBin_mdate = "No Recycle Bin found"
            self.FilteredDeletedFiles = []
            self.FilteredRenamedFiles = []
            self.FilteredReplacedFiles = []
            self.Results = []
            
            # Step 1: Clear UI
            window.evaluate_js("clearAllResults();")
            
            # Step 2: Dump USN Journal
            window.evaluate_js("updateStatus('Dumping USN Journal...', 20, 0, '0 seconds', 'N/A');")
            self.USNDump()
            
            # Step 3: Parse USN Journal
            window.evaluate_js("updateStatus('Parsing USN Journal entries...', 40, 0, '0 seconds', 'N/A');")
            Journal = self.USNParse()
            
            if Journal is None:
                window.evaluate_js("updateStatus('Journal not found or empty', 100, 0, '0 seconds', 'N/A');")
                self.is_scanning = False
                return
            
            DeletedFiles, RenamedFiles, ReplacedFiles = Journal
            
            # Step 4: Scan Explorer strings with FULL PATHS
            window.evaluate_js("updateStatus('Scanning Explorer process memory...', 60, 0, '0 seconds', 'N/A');")
            self.ExecutedFiles = []  # Reset
            self.explorerdump_with_paths()  # Use new method with paths
            
            # Step 5: Scan Recycle Bin
            window.evaluate_js("updateStatus('Scanning Recycle Bin...', 80, 0, '0 seconds', 'N/A');")
            self.scan_recycle_bin()
            
            # Step 6: Filter deleted files to only include actual executable extensions
            for item in DeletedFiles:
                filename = item.split(":::")[0]
                if any(filename.lower().endswith(ext) for ext in actual_executable_extensions):
                    self.FilteredDeletedFiles.append(item)
            
            # Step 7: Check which filtered deleted files were also executed
            # Now ExecutedFiles contains full paths, so we need to extract just filenames
            executed_filenames = {os.path.basename(path).lower() for path in self.ExecutedFiles}
            
            for item in self.FilteredDeletedFiles:
                filename = item.split(":::")[0].lower()
                if filename in executed_filenames:
                    # Find the matching full path from ExecutedFiles
                    full_path = None
                    for path in self.ExecutedFiles:
                        if os.path.basename(path).lower() == filename:
                            full_path = path
                            break
                    
                    if full_path:
                        timestamp = item.split(":::")[1]
                        self.Results.append(f"{filename}|{full_path}|{timestamp}")
            
            # Step 8: Filter renamed files
            for item in RenamedFiles:
                if len(item.split(":::")) == 3:  # Has old name, new name, timestamp
                    old_name = item.split(":::")[0]
                    new_name = item.split(":::")[1]
                    if (any(old_name.lower().endswith(ext) for ext in executable_extensions) or
                        any(new_name.lower().endswith(ext) for ext in executable_extensions)):
                        self.FilteredRenamedFiles.append(item)
                elif self.patron3.match(item.split(":::")[1]) != None:
                    # This is a Recycle Bin entry
                    filename = item.split(':::')[0]
                    if any(filename.lower().endswith(ext) for ext in executable_extensions):
                        self.RecycleBin.append(item.split(':::')[0] + ":::" + item.split(':::')[2])
            
            # Step 9: Filter replaced files
            for item in ReplacedFiles:
                filename = item.split(":::")[0]
                if any(filename.lower().endswith(ext) for ext in executable_extensions):
                    self.FilteredReplacedFiles.append(item)
            
            # Step 10: Apply deduplication
            deduped = self.deduplicate_results(
                self.Results,
                self.FilteredRenamedFiles,
                self.FilteredReplacedFiles,
                self.RecycleBin_files,
                self.RecycleBin
            )
            
            # Calculate scan time
            scan_time_seconds = int((datetime.now() - self.start_time).total_seconds())
            
            # Prepare results
            self.results = {
                'deletedFiles': deduped['deletedFiles'],
                'renamedFiles': deduped['renamedFiles'],
                'replacedFiles': deduped['replacedFiles'],
                'recycleBinFiles': deduped['recycleBinFiles'],
                'journalRecycleBin': deduped['journalRecycleBin'],
                'scanTime': f"{scan_time_seconds} seconds",
                'recycleBinDate': self.RecycleBin_mdate
            }
            
            # Send results to UI
            results_json = json.dumps(self.results)
            window.evaluate_js(f"loadAllEntries({results_json});")
            
            # Update final status
            total_entries = (len(deduped['deletedFiles']) + len(deduped['renamedFiles']) + 
                        len(deduped['replacedFiles']) + len(deduped['recycleBinFiles']) + 
                        len(deduped['journalRecycleBin']))
            window.evaluate_js(f"updateStatus('Analysis Complete', 100, {total_entries}, '{scan_time_seconds} seconds', '{self.RecycleBin_mdate}');")
            
            # Schedule auto-stop after 2 seconds
            threading.Timer(2.0, self.auto_stop_and_update_ui, args=(window,)).start()

        except Exception as e:
            error_msg = str(e).replace("'", "\\'")
            window.evaluate_js(f"showError('Analysis failed: {error_msg}');")
            # Auto-stop even on error
            threading.Timer(2.0, self.auto_stop_and_update_ui, args=(window,)).start()
        finally:
            self.is_scanning = False
            self.done = True

    # Add this new method to get full paths from explorer memory
    def explorerdump_with_paths(self):
        """Get executed files with full paths from explorer memory"""
        xxstrings_path = self.download_xxstrings()
        pid = None
        
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == 'explorer.exe':
                pid = proc.info['pid']
                break
        
        if pid and os.path.exists(xxstrings_path):
            try:
                explorerstrings = subprocess.check_output(
                    f'"{xxstrings_path}" -p {pid}', 
                    shell=True,
                    stderr=subprocess.STDOUT,
                    timeout=60
                )
                
                # Parse the output - get full paths
                for linea in explorerstrings.decode('utf-8', errors='ignore').splitlines():
                    bebeto = self.patron.search(linea)
                    if bebeto != None:
                        full_path = bebeto.group(0)
                        # Clean up the path
                        cleaned_path = full_path.replace("file:///", "").replace("%20", " ")
                        cleaned_path = cleaned_path.replace("/", "\\")
                        
                        # Check if it's a real file
                        if os.path.exists(cleaned_path):
                            filename = os.path.basename(cleaned_path)
                            if any(filename.lower().endswith(ext) for ext in actual_executable_extensions):
                                self.ExecutedFiles.append(cleaned_path)
                        else:
                            # Even if file doesn't exist now, check if it has executable extension
                            filename = os.path.basename(cleaned_path)
                            if any(filename.lower().endswith(ext) for ext in actual_executable_extensions):
                                self.ExecutedFiles.append(cleaned_path)
                
                # Remove duplicates while preserving order
                self.ExecutedFiles = list(dict.fromkeys(self.ExecutedFiles))
                
            except subprocess.CalledProcessError as grepexc:
                print(f"error code {grepexc.returncode}, {grepexc.output}")
            except subprocess.TimeoutExpired:
                print("xxstrings timed out")
            except Exception as e:
                print(f"Error in explorerdump_with_paths: {e}")
    
    def get_results(self):
        return self.results
    
    def stop_analysis(self):
        self.is_scanning = False

    def auto_stop_and_update_ui(self, window):
        """Automatically stop analysis and update UI after completion"""
        # Stop the analysis flag
        self.is_scanning = False
        self.done = True
        
        # Update UI buttons - this needs to be called from the main thread
        # We'll send a message to the UI to update the buttons
        try:
            window.evaluate_js("""
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('stopBtn').disabled = true;
                document.getElementById('clearBtn').disabled = false;
                document.getElementById('exportBtn').disabled = false;
                
                // Update button text
                const scanBtnText = document.querySelector('#scanBtn .button-text');
                const scanBtnLoading = document.querySelector('#scanBtn .button-loading');
                if (scanBtnText && scanBtnLoading) {
                    scanBtnText.style.display = 'inline';
                    scanBtnLoading.style.display = 'none';
                }
                
                // Remove scanning glow
                document.getElementById('scanBtn').classList.remove('scanning-glow');
                
                // Update status text class
                document.getElementById('statusText').className = 'status-text';
            """)
        except Exception as e:
            print(f"Error updating UI: {e}")
    
    def clear_results(self):
        self.results = {}
    
    def export_results(self, filename=None):
        if not filename:
            filename = f"DREParser_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        
        return filename

class Api:
    def __init__(self):
        self.parser = DREParser()
    
    def start_analysis(self):
        if self.parser.is_scanning or not webview.windows:
            return False
        thread = threading.Thread(target=self.parser.perform_analysis, args=(webview.windows[0],))
        thread.daemon = True
        thread.start()
        return True
    
    def stop_analysis(self):
        self.parser.stop_analysis()
        return True
    
    def get_results(self):
        return self.parser.get_results()
    
    def clear_results(self):
        self.parser.clear_results()
        return True
    
    def export_results(self):
        try:
            filename = self.parser.export_results()
            return {'success': True, 'filename': filename}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def window_minimize(self):
        if webview.windows:
            webview.windows[0].minimize()
        return True
    
    def window_maximize(self):
        if webview.windows:
            webview.windows[0].toggle_fullscreen()
        return True
    
    def window_close(self):
        if webview.windows:
            webview.windows[0].destroy()
        return True
    
    def window_move(self, x, y):
        if webview.windows:
            webview.windows[0].move(x, y)
        return True

def get_web_files_path():
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, 'web')
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')

def create_fallback_html():
    return """<!DOCTYPE html><html><head><title>DREParser - Error</title>
<style>body{background:#0f172a;color:white;font-family:Arial;padding:20px;}
.error{color:#ef4444;background:rgba(239,68,68,0.1);padding:20px;border-radius:8px;}</style>
</head><body><h1>DREParser</h1><div class="error">Web files not found.</div></body></html>"""

if __name__ == '__main__':
    if not is_admin():
        run_as_admin()
    
    if getattr(sys, 'frozen', False) and sys.platform == 'win32':
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    api = Api()
    web_path = get_web_files_path()
    ui_path = os.path.join(web_path, 'UI.html')
    
    if not os.path.exists(web_path):
        os.makedirs(web_path, exist_ok=True)
    
    url = ui_path if os.path.exists(ui_path) else None
    html = create_fallback_html() if not url else None
    
    window = webview.create_window(
        'DREParser - Digital Forensic Analysis',
        url=url, html=html,
        width=1400, height=900, resizable=True,
        frameless=True, easy_drag=False, min_size=(1000, 700),
        js_api=api
    )
    
    webview.start(debug=False)