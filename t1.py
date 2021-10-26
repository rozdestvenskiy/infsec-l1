import struct

elf = 'curl-amd64'
macho = 'ip.so'

FOR ELF

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
    currentPoint = 32
elif machoMagicNumber == 0xFEEDFACE:
    print('File type: Mach-O')
    print('Architecture: x32')
    currentPoint = 28
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
machoFlags = 0x100085
flags = machoFlags
print('Flags: ', hex(flags))
if (flags & (1 << 0)) >> 0 == 1:
    print("\tMH_NOUNDEFS")
if (flags & (1 << 1)) >> 1 == 1:
    print("\tMH_INCRLINK")
if (flags & (1 << 2)) >> 2 == 1:
    print("\tMH_DYLDLINK")
if (flags & (1 << 3)) >> 3 == 1:
    print("\tMH_BINDATLOAD")
if (flags & (1 << 4)) >> 4 == 1:
    print("\tMH_PREBOUND")
if (flags & (1 << 5)) >> 5 == 1:
    print("\tMH_SPLIT_SEGS")
if (flags & (1 << 6)) >> 6 == 1:
    print("\tMH_LAZY_INIT")
if (flags & (1 << 7)) >> 7 == 1:
    print("\tMH_TWOLEVEL")
if (flags & (1 << 8)) >> 8 == 1:
    print("\tMH_FORCE_FLAT")
if (flags & (1 << 9)) >> 9 == 1:
    print("\tMH_NOMULTIDEFS")
if (flags & (1 << 10)) >> 10 == 1:
    print("\tMH_NOFIXPREBINDING")
if (flags & (1 << 11)) >> 11 == 1:
    print("\tMH_PREBINDABLE")
if (flags & (1 << 12)) >> 12 == 1:
    print("\tMH_ALLMODSBOUND")
if (flags & (1 << 13)) >> 13 == 1:
    print("\tMH_SUBSECTIONS_VIA_SYMBOLS")
if (flags & (1 << 14)) >> 14 == 1:
    print("\tMH_CANONICAL")
if (flags & (1 << 15)) >> 15 == 1:
    print("\tMH_WEAK_DEFINES")
if (flags & (1 << 16)) >> 16 == 1:
    print("\tMH_BINDS_TO_WEAK")
if (flags & (1 << 17)) >> 17 == 1:
    print("\tMH_ALLOW_STACK_EXECUTION")
if (flags & (1 << 18)) >> 18 == 1:
    print("\tMH_ROOT_SAFE")
if (flags & (1 << 19)) >> 19 == 1:
    print("\tMH_SETUID_SAFE")
if (flags & (1 << 20)) >> 20 == 1:
    print("\tMH_NO_REEXPORTED_DYLIBS")
if (flags & (1 << 21)) >> 21 == 1:
    print("\tMH_PIE")
if (flags & (1 << 22)) >> 22 == 1:
    print("\tMH_DEAD_STRIPPABLE_DYLIB")
if (flags & (1 << 23)) >> 23 == 1:
    print("\tMH_HAS_TLV_DESCRIPTORS")
if (flags & (1 << 24)) >> 24 == 1:
    print("\tMH_NO_HEAP_EXECUTION")

#machoMagicNumber = struct.unpack('16B', d[0:16])


print('-----------------------')
print()
print()




# print('-------TASK-7----------')
machoLoadCommandTemplate = '2I'
machoSegmentTemplate = '2I16c4Q2i2I'
machoSectionTemplate = '16c16c2Q8I'
print("%s%25s%30s%30s" % ('Section name', 'Segment name', 'Section offset', 'Section addr'))
for i in range(machoNumberCommands):
    CurrentLoadCommand = struct.unpack(machoLoadCommandTemplate, machoData[currentPoint:currentPoint + 8])
    CurrentLoadCommandType = CurrentLoadCommand[0]
    CurrentLoadCommandSize = CurrentLoadCommand[1]
    #print(hex(CurrentLoadCommandType), hex(CurrentLoadCommandSize))
    #print(hex(CurrentLoadCommandType))
    if CurrentLoadCommandType == 0x19:
        #That means this is segment (LC_SEGMENT_64)
        CurrentSegment = struct.unpack(machoSegmentTemplate, machoData[currentPoint:currentPoint + 72])
        CurrentSegmentCmd = CurrentSegment[0]
        CurrentSegmentSize = CurrentSegment[1]
        CurrentSegmentName = str(CurrentSegment[2:18])
        CurrentSegmentVMAddr = CurrentSegment[18]
        CurrentSegmentVMSize = CurrentSegment[19]
        CurrentSegmentFileOff = CurrentSegment[20]
        CurrentSegmentFileSize = CurrentSegment[21]
        CurrentSegmentMaxProt = CurrentSegment[22]
        CurrentSegmentInitProt = CurrentSegment[23]
        CurrentSegmentNSects = CurrentSegment[24]
        CurrentSegmentFlags = CurrentSegment[25]

        currentPointSects = currentPoint + 72



        for j in range(CurrentSegmentNSects):
            CurrentSection = struct.unpack(machoSectionTemplate, machoData[currentPointSects:currentPointSects + 80])
            CurrentSectionName = CurrentSection[0:16]
            name = ''
            for k in range(16):
                name += CurrentSectionName[k].decode('utf-8', 'backslashreplace')
            CurrentSectionSegName = CurrentSection[16:32]
            nameSeg = ''
            for k in range(16):
                nameSeg += CurrentSectionSegName[k].decode('utf-8', 'backslashreplace')
            CurrentSectionAddr = CurrentSection[32]
            CurrentSectionSize = CurrentSection[33]
            CurrentSectionOffset = CurrentSection[34]
            CurrentSectionAlign = CurrentSection[35]
            CurrentSectionRelOff = CurrentSection[36]
            CurrentSectionNReloc = CurrentSection[37]
            CurrentSectionFlags = CurrentSection[38]
            CurrentSectionRes1 = CurrentSection[39]
            CurrentSectionRes2 = CurrentSection[40]
            CurrentSectionRes3 = CurrentSection[41]
            print("%16s%35s%30s%30s" % (name, nameSeg, hex(CurrentSectionOffset), hex(CurrentSectionAddr)))
            currentPointSects += 80
    #currentPoint += CurrentLoadCommandSize
    currentPoint += CurrentLoadCommandSize
print('-----------------------')
print()
print()

#print('-------TASK-9----------')








#print('-----------------------')
#print()
#print()
