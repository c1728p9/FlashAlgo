from __future__ import print_function
import sys

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from jinja2 import Template, StrictUndefined
from struct import unpack
import copy

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


# x-Get symbol table
# x-Get all allocatable sections - should be "PrgCode", "PrgData" and "DevDscr"
# -Get sections PrgCode and PrgData
# x-Extract data
# x-Build output data - RO, RW, ZI regions
# -Build target output - 


def main():
    TEMPLATE_PATH = "py_blob.tmpl"
    ELF_FILE = "mk64f12.axf"
    with open(ELF_FILE, 'rb') as file_handle:
        elffile = ELFFile(file_handle)
        symbols = get_required_symbols(elffile)
        flash_algo = get_flash_algo(elffile)
        #flash_info = get_flash_info(elffile)

    WORDS_PER_LINE = 6
    algo_data = flash_algo["data"]
    algo_words = unpack(str(len(algo_data) // 4) + "I", algo_data)
    algo_string = ""
    for i in range(len(algo_words)):
        algo_string += "0x%08x" % algo_words[i] + ", "
        if ((i + 1) % WORDS_PER_LINE) == 0:
            algo_string += "\n    "

    dic = {}
    dic["func"] = copy.deepcopy(symbols)
    dic["algo"] = copy.deepcopy(flash_algo)
    dic["algo"]["data"] = algo_string

    template_path = TEMPLATE_PATH
    template_text = open(template_path).read()
    template = Template(template_text)
    target_text = template.render(dic)

    with open("output.txt", "wb") as file_handle:
        file_handle.write(target_text)


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
    RO_SECTION_INDEX = 1
    RW_SECTION_INDEX = 2
    ZI_SECTION_INDEX = 3
    STATIC_BASE_SYMBOL_NAME = "$d.realdata"
    ro_section = None
    rw_section = None
    zi_section = None

    # Find requried sections
    for index, section in enumerate(elffile.iter_sections()):
        if bytes2str(section.name) == "PrgCode":
            if section['sh_type'] == "SHT_PROGBITS":
                if ro_section is None:
                    ro_section = section
                elif index != RO_SECTION_INDEX:
                    print("Wrong ro section number")
                else:
                    print("Extra ro section")
            else:
                print("Unexpected section type in PrgCode")
        if bytes2str(section.name) == "PrgData":
            if section['sh_type'] == "SHT_PROGBITS":
                if rw_section is None:
                    rw_section = section
                elif index != RW_SECTION_INDEX:
                    print("Wrong rw section number")
                else:
                    print("Extra rw section")
            elif section['sh_type'] == "SHT_NOBITS":
                if zi_section is None:
                    zi_section = section
                elif index != ZI_SECTION_INDEX:
                    print("Wrong zi section number")
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

    # Grab PrgData static base
    section = elffile.get_section_by_name(b'.symtab')
    if not section:
        print("Missing symbol table")
        return None
    if not isinstance(section, SymbolTableSection):
        print("Invalid symbol table section")
        return None
    static_base = None
    for symbol in section.iter_symbols():
        name_str = bytes2str(symbol.name)
        if ((name_str == STATIC_BASE_SYMBOL_NAME) and
                (symbol['st_shndx'] == RW_SECTION_INDEX)):
            if static_base is not None:
                print("Duplicate static base symbols")
                return None
            static_base = symbol['st_value']

    # Build the algo
    algo = {}
    algo["static_base"] = static_base
    algo["ro_start"] = ro_section['sh_addr']
    algo["ro_size"] = ro_section['sh_size']
    algo["rw_start"] = rw_section['sh_addr']
    algo["rw_size"] = rw_section['sh_size']
    algo["zi_start"] = zi_section['sh_addr']
    algo["zi_size"] = zi_section['sh_size']

    # Check section ordering
    if algo["ro_start"] != 0:
        print("RO section does not start at address 0")
        return None
    if algo["ro_start"] + algo["ro_size"] != algo["rw_start"]:
        print("RW section does not follow RO section")
        return None
    if algo["rw_start"] + algo["rw_size"] != algo["zi_start"]:
        print("ZI section does not follow RW section")
        return None

    # Attach data to the flash algo
    algo_size = algo["rw_start"] + algo["rw_size"] + algo["zi_size"]
    algo_data = bytearray(algo_size)
    ro_data = ro_section.data()
    algo_data[algo["ro_start"]:algo["ro_start"] + algo["ro_size"]] = ro_data
    rw_data = rw_section.data()
    algo_data[algo["rw_start"]:algo["rw_start"] + algo["rw_size"]] = rw_data
    # ZI is already zeroed

    algo['data'] = algo_data

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