from __future__ import print_function
import sys

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

DEVICE_INFO = "FlashDevice"

REQUIRED_SYMBOLS = set([
    "Init",
    "UnInit",
    "EraseChip",
    "EraseSector",
    "ProgramPage",
])

EXTRA_SYMBOLS = set([
    "BlankCheck",
    "FlashCommandSequence",
    "FlashEraseAllBlock",
    "FlashEraseBlock",
    "FlashEraseSector",
    "FlashInit",
    "FlashVerifySection",
])

ALL_SYMBOLS = REQUIRED_SYMBOLS | EXTRA_SYMBOLS | set([DEVICE_INFO])


REQUIRED_DESCRIPTOR_SECTIONS = set([
    "DevDscr"
    ])


class FlashAlgo(object):

    def __init__(self):
        self.algo_data = None
        self.ro_start = None
        self.ro_size = None
        self.rw_start = None
        self.rw_size = None
        self.zi_start = None
        self.zi_size = None


# x-Get symbol table
# -Get all allocatable sections - should be "PrgCode", "PrgData" and "DevDscr"
# -Get sections PrgCode and PrgData
# -Extract data
# -Build output data - RO, RW, ZI regions
# -Build target output - 


def main():
    ELF_FILE = "MK_P1M0.FLM"
    with open(ELF_FILE, 'rb') as file_handle:
        elffile = ELFFile(file_handle)
        symbols = get_required_symbols(elffile)
        flash_algo = get_flash_algo(elffile)
        flash_info = get_flash_info(elffile)

        output = {}
        for symbol in REQUIRED_SYMBOLS:
            output[symbol] = symbols[symbol]
        output["ro_start"] = flash_algo.ro_start
        output["ro_size"] = flash_algo.ro_size
        output["rw_start"] = flash_algo.rw_start
        output["rw_size"] = flash_algo.rw_size
        output["zi_start"] = flash_algo.zi_start
        output["zi_size"] = flash_algo.zi_size
        output["algo_bytes"] = list(flash_algo.algo_data)

    with open("output.txt", "wb") as file_handle:
        file_handle.write(str(output))


def get_required_symbols(elffile):
    section = elffile.get_section_by_name(b'.symtab')
    if not section:
        print("Missing symbol table")
        return None

    if not isinstance(section, SymbolTableSection):
        print("Invalid symbol table section")
        return None

    symbols = {}
    for symbol in section.iter_symbols():
        name_str = bytes2str(symbol.name)
        if name_str in ALL_SYMBOLS:
            if name_str in symbols:
                print("Warning - duplicate symbol %s" % name_str)
            symbols[name_str] = symbol['st_value']

    symbols_set = set(symbols.keys())
    if (symbols_set & REQUIRED_SYMBOLS) != REQUIRED_SYMBOLS:
        missing_symbols_list = list(REQUIRED_SYMBOLS - symbols_set)
        missing_symbols_list.sort()
        print("File is missing symbols:")
        for symbol in missing_symbols_list:
            print("    %s" % symbol)
        return None

    return symbols


def get_flash_algo(elffile):
    ro_section = None
    rw_section = None
    zi_section = None

    # Find requried sections
    for section in elffile.iter_sections():
        if bytes2str(section.name) == "PrgCode":
            if section['sh_type'] == "SHT_PROGBITS":
                if ro_section is None:
                    ro_section = section
                else:
                    print("Extra ro section")
            else:
                print("Unexpected section type in PrgCode")
        if bytes2str(section.name) == "PrgData":
            if section['sh_type'] == "SHT_PROGBITS":
                if rw_section is None:
                    rw_section = section
                else:
                    print("Extra rw section")
            elif section['sh_type'] == "SHT_NOBITS":
                if zi_section is None:
                    zi_section = section
                else:
                    print("Extra zi section")
            else:
                print("Unexpected section type in PrgData")

    # Make sure all required sections are present
    if ro_section is None:
        print("Missing ro section")
        return None
    if rw_section is None:
        print("Missing rw section")
        return None
    if zi_section is None:
        print("Missing zi section")
        return None

    # Build the algo
    algo = FlashAlgo()
    algo.ro_start = ro_section['sh_addr']
    algo.ro_size = ro_section['sh_size']
    algo.rw_start = rw_section['sh_addr']
    algo.rw_size = rw_section['sh_size']
    algo.zi_start = zi_section['sh_addr']
    algo.zi_size = zi_section['sh_size']

    # Check section ordering
    if algo.ro_start != 0:
        print("RO section does not start at address 0")
        return None
    if algo.ro_start + algo.ro_size != algo.rw_start:
        print("RW section does not follow RO section")
        return None
    if algo.rw_start + algo.rw_size != algo.zi_start:
        print("ZI section does not follow RW section")
        return None

    # Attach data to the flash algo
    algo_size = algo.rw_start + algo.rw_size + algo.zi_size
    algo_data = bytearray(algo_size)
    ro_data = ro_section.data()
    algo_data[algo.ro_start:algo.ro_start + algo.ro_size] = ro_data
    rw_data = rw_section.data()
    algo_data[algo.rw_start:algo.rw_start + algo.rw_size] = rw_data
    # ZI is already zeroed
    algo.algo_data = algo_data

    return algo


def get_flash_info(elffile):
    return None


if __name__ == '__main__':
    main()


# struct FlashDevice  {
#    unsigned short     Vers;    // Version Number and Architecture
#    char       DevName[128];    // Device Name and Description
#    unsigned short  DevType;    // Device Type: ONCHIP, EXT8BIT, EXT16BIT, ...
#    unsigned long    DevAdr;    // Default Device Start Address
#    unsigned long     szDev;    // Total Size of Device
#    unsigned long    szPage;    // Programming Page Size
#    unsigned long       Res;    // Reserved for future Extension
#    unsigned char  valEmpty;    // Content of Erased Memory
# 
#    unsigned long    toProg;    // Time Out of Program Page Function
#    unsigned long   toErase;    // Time Out of Erase Sector Function
# 
#    struct FlashSectors sectors[SECTOR_NUM];
# };


# #define SECTOR_END 0xFFFFFFFF, 0xFFFFFFFF

# #define VERS       1           // Interface Version 1.01
# 
# #define UNKNOWN    0           // Unknown
# #define ONCHIP     1           // On-chip Flash Memory
# #define EXT8BIT    2           // External Flash Device on 8-bit  Bus
# #define EXT16BIT   3           // External Flash Device on 16-bit Bus
# #define EXT32BIT   4           // External Flash Device on 32-bit Bus
# #define EXTSPI     5           // External Flash Device on SPI

# #ifdef MKP1024
# struct FlashDevice const FlashDevice  =  {
#    FLASH_DRV_VERS,             // Driver Version, do not modify!
#    "MKxxN 1024KB Prog Flash",  // Device Name 
#    ONCHIP,                     // Device Type
#    0x00000000,                 // Device Start Address
#    0x00100000,                 // Device Size (1MB)
#    512,                        // Programming Page Size
#    0,                          // Reserved, must be 0
#    0xFF,                       // Initial Content of Erased Memory
#    1000,                       // Program Page Timeout 1000 mSec
#    3000,                       // Erase Sector Timeout 3000 mSec
# 
# // Specify Size and Address of Sectors
#    0x001000, 0x000000,         // Sector Size  4kB (256 Sectors)
#    SECTOR_END
# };
# #endif


# #ifdef LPC11U6X                // = LPC11E6X
# 
# #ifdef FLASH_256
# struct FlashDevice const FlashDevice  =  {
#    FLASH_DRV_VERS,             // Driver Version, do not modify!
#    "LPC11E6x/U6x IAP 256kB Flash", // Device Name
#    ONCHIP,                     // Device Type
#    0x00000000,                 // Device Start Address
#    0x00040000,                 // Device Size (256kB)
#    1024,                       // Programming Page Size
#    0,                          // Reserved, must be 0
#    0xFF,                       // Initial Content of Erased Memory
#    300,                        // Program Page Timeout 300 mSec
#    3000,                       // Erase Sector Timeout 3000 mSec
# 
# // Specify Size and Address of Sectors
#    0x001000, 0x000000,         // Sector Size  4kB (24 Sectors)
#    0x008000, 0x018000,         // Sector Size 32kB (5 Sectorss)
#    SECTOR_END
# };
# #endif