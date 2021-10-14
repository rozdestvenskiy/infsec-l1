import struct

elf = 'curl-amd64'
macho = 'ip.o'

# FOR ELF

elfFile = open(elf, 'rb')
elfData = elfFile.read()

#PARSING HEADER


elfHeaderTemplate = '<16B2HI3QI6H'
elfHeader = struct.unpack(elfHeaderTemplate, elfData[0:64])
elfMagicNumber = elfHeader[0:16]
elfObjFileType = elfHeader[16]
elfArchitecture = elfHeader[17]
elfVersion = elfHeader[18]
elfEntryPoint = elfHeader[19]
elfProgramOffset = elfHeader[20]
elfSectionOffset = elfHeader[21]
elfProcFlags = elfHeader[22]
elfHeaderSize = elfHeader[23]
elfProgramHeaderTableEntrySize = elfHeader[24]
elfProgramHeaderTableEntryCount = elfHeader[25]
elfSectionHeaderTableEntrySize = elfHeader[26]
elfSectionHeaderTableEntryCount = elfHeader[27]
elfSectionHeaderStringTableIndex = elfHeader[28]
#elfMagicNumber = struct.unpack('16B', d[0:16])
STDelfMagicNumber = (0x7F, 0x45, 0x4C, 0x46)

print('-------TASK-1----------')

if elfMagicNumber[0:4] != STDelfMagicNumber:
    print('ERROR: File is not ELF')
    #quit()
else:
    print('File type: ELF')

if elfObjFileType == 0:
    print('File type: undefined')
elif elfObjFileType == 1:
    print('File type: lib')
elif elfObjFileType == 2:
    print('File type: exec')
elif elfObjFileType == 3:
    print('File type: dll')


if hex(elfArchitecture) == 0x3E:
    print('Archutecture: ', elfArchitecture, '(AMD x86-64)')
elif hex(elfArchitecture) == 0x28:
    print('Archutecture: ', elfArchitecture, '(ARM)')
elif hex(elfArchitecture) == 0xAF:
    print('Archutecture: ', elfArchitecture, '(ELBRUS)')
print('Entry point: ', hex(elfEntryPoint), sep='')
print('Segment offset: ', hex(elfProgramOffset), sep='')
print('Segment count: ', elfProgramHeaderTableEntryCount)
print('Section offset: ', hex(elfSectionOffset), sep='')
print('Section count: ', elfSectionHeaderTableEntryCount)
print('-----------------------')
print()
print()






print('-------TASK-3----------')
if elfSectionOffset == 0:
    print('There are not any sections in file')

elfSectionTemplate = '<2I4Q2I2Q'
pointer = elfSectionOffset
size = elfSectionHeaderTableEntrySize
print('Section name\tSection type\tSection offset\tSection addr\t')
types = ['SHT_NULL', 'SHT_PROGBITS', 'SHT_SYMTAB', 'SHT_STRTAB', 'SHT_RELA', 'SHT_HASH', 'SHT_DYNAMIC', 'SHT_NOTE', 'SHT_NOBITS', 'SHT_REL', 'SHT_SHLIB', 'SHT_DYNSYM', 'SHT_INIT_ARRAY', 'SHT_FINI_ARRAY', 'SHT_PREINIT_ARRA', 'SHT_GROUP', 'SHT_SYMTAB_SHNDX', 'SHT_LOOS', 'SHT_HIOS', 'SHT_LOPROC', 'SHT_HIPROC', 'SHT_LOUSER', 'SHT_HIUSER']

for i in range(elfSectionHeaderTableEntryCount):
    section = struct.unpack(elfSectionTemplate, elfData[pointer:pointer + size])
    sectionName = section[0]
    sectionType = section[1]
    sectionFlags = section[2]
    sectionAddr = section[3]
    sectionOffset = section[4]
    sectionSize = section[5]
    sectionLink = section[6]
    sectionInfo = section[7]
    sectionAllign = section[8]
    sectionEntrySize = section[9]
    pointer += size
    print("%12d%16s%18s%14s" % (sectionName, types[sectionType], hex(sectionOffset), hex(sectionAddr)))

print('-----------------------')
print()
print()




print('-------TASK-5----------')
machoFile = open(macho, 'rb')
machoData = machoFile.read()

#PARSING HEADER


machoHeaderTemplate = '<L2I4L'
STDmachoMagicNumber = 0xFEEDFACF
machoHeader = struct.unpack(machoHeaderTemplate, machoData[0:28])
machoMagicNumber = machoHeader[0]

if machoMagicNumber == 0xFEEDFACF:
    print('File type: Mach-O')
    print('Architecture: x64')
elif machoMagicNumber == 0xFEEDFACE:
    print('File type: Mach-O')
    print('Architecture: x32')
else:
    print('ERROR: File is not Mach-O')

machoCPUType = machoHeader[1]
machoMachine = machoHeader[2]
machoFileType = machoHeader[3]
if machoFileType == 0:
    print('File type: undefined')
elif machoFileType == 1:
    print('File type: lib')
elif machoFileType == 2:
    print('File type: exec')
elif machoFileType == 3:
    print('File type: dll')
machoNumberCommands = machoHeader[4]
print('Commands number: ', machoNumberCommands)
machoSizeCommands = machoHeader[5]
machoFlags = machoHeader[6]
flags = machoFlags
print('Flags: ', hex(flags))
if (flags << 31 >> 31) == 1:
    print("\tMH_NOUNDEFS")
if (flags << 30 >> 31) == 1:
    print("\tMH_INCRLINK")
if (flags << 29 >> 31) == 1:
    print("\tMH_DYLDLINK")
if (flags << 28 >> 31) == 1:
    print("\tMH_BINDATLOAD")
if (flags << 27 >> 31) == 1:
    print("\tMH_PREBOUND")
if (flags << 26 >> 31) == 1:
    print("\tMH_SPLIT_SEGS")
if (flags << 25 >> 31) == 1:
    print("\tMH_LAZY_INIT")
if (flags << 24 >> 31) == 1:
    print("\tMH_TWOLEVEL")
if (flags << 23 >> 31) == 1:
    print("\tMH_FORCE_FLAT")
if (flags << 22 >> 31) == 1:
    print("\tMH_NOMULTIDEFS")
if (flags << 21 >> 31) == 1:
    print("\tMH_NOFIXPREBINDING")
if (flags << 20 >> 31) == 1:
    print("\tMH_PREBINDABLE")
if (flags << 19 >> 31) == 1:
    print("\tMH_ALLMODSBOUND")
if (flags << 18 >> 31) == 1:
    print("\tMH_SUBSECTIONS_VIA_SYMBOLS")
if (flags << 17 >> 31) == 1:
    print("\tMH_CANONICAL")
if (flags << 16 >> 31) == 1:
    print("\tMH_WEAK_DEFINES")
if (flags << 15 >> 31) == 1:
    print("\tMH_BINDS_TO_WEAK")
if (flags << 14 >> 31) == 1:
    print("\tMH_ALLOW_STACK_EXECUTION")
if (flags << 13 >> 31) == 1:
    print("\tMH_ROOT_SAFE")
if (flags << 12 >> 31) == 1:
    print("\tMH_SETUID_SAFE")
if (flags << 11 >> 31) == 1:
    print("\tMH_NO_REEXPORTED_DYLIBS")
if (flags << 10 >> 31) == 1:
    print("\tMH_PIE")
if (flags << 9 >> 31) == 1:
    print("\tMH_DEAD_STRIPPABLE_DYLIB")
if (flags << 8 >> 31) == 1:
    print("\tMH_HAS_TLV_DESCRIPTORS")
if (flags << 7 >> 31) == 1:
    print("\tMH_NO_HEAP_EXECUTION")

#machoMagicNumber = struct.unpack('16B', d[0:16])


print('-----------------------')
print()
print()




# print('-------TASK-7----------')
# if elfSectionOffset == 0:
#     print('There are not any sections in file')
#
# machoSectionTemplate = '<16B16B9L'
# pointer = elfSectionOffset
# size = elfSectionHeaderTableEntrySize
# print('Section name\tSection type\tSection offset\tSection addr\t')
# types = ['SHT_NULL', 'SHT_PROGBITS', 'SHT_SYMTAB', 'SHT_STRTAB', 'SHT_RELA', 'SHT_HASH', 'SHT_DYNAMIC', 'SHT_NOTE', 'SHT_NOBITS', 'SHT_REL', 'SHT_SHLIB', 'SHT_DYNSYM', 'SHT_INIT_ARRAY', 'SHT_FINI_ARRAY', 'SHT_PREINIT_ARRA', 'SHT_GROUP', 'SHT_SYMTAB_SHNDX', 'SHT_LOOS', 'SHT_HIOS', 'SHT_LOPROC', 'SHT_HIPROC', 'SHT_LOUSER', 'SHT_HIUSER']
#
# for i in range(elfSectionHeaderTableEntryCount):
#     section = struct.unpack(elfSectionTemplate, elfData[pointer:pointer + size])
#     sectionName = section[0]
#     sectionType = section[1]
#     sectionFlags = section[2]
#     sectionAddr = section[3]
#     sectionOffset = section[4]
#     sectionSize = section[5]
#     sectionLink = section[6]
#     sectionInfo = section[7]
#     sectionAllign = section[8]
#     sectionEntrySize = section[9]
#     pointer += size
#     print("%12d%16s%18s%14s" % (sectionName, types[sectionType], hex(sectionOffset), hex(sectionAddr)))
#
# print('-----------------------')
# print()
# print()
