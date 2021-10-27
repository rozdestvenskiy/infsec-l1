import struct
print('---------TASK-1---------')
elf = 'cat'
elfFile = open(elf, 'rb')
elfData = elfFile.read()

# PARSING HEADER

elfHeaderTemplate = '16B2HI3QI6H'
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
STDelfMagicNumber = (0x7F, 0x45, 0x4C, 0x46)

if elfMagicNumber[0:4] != STDelfMagicNumber:
    print('ERROR: File is not ELF')
    exit()
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
print('--------------------------')
print()
print()

if elfSectionOffset == 0:
    print('There are not any sections in file')
    exit()

elfSectionTemplate = '2I4Q2I2Q'
pointer = elfSectionOffset
size = elfSectionHeaderTableEntrySize
#print('Section name\tSection type\tSection offset\tSection addr\t')
print("%4s%20s%20s%20s%20s" % (
    '[x]', 'Section name', 'Section type', 'Section offset', 'Section addr'))
types = ['NULL', 'PROGBITS', 'SYMTAB', 'STRTAB', 'RELA', 'HASH', 'DYNAMIC', 'NOTE', 'NOBITS', 'REL', 'SHLIB', 'DYNSYM',
         'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRA', 'GROUP', 'SYMTAB_SHNDX', 'LOOS', 'HIOS', 'LOPROC', 'HIPROC', 'LOUSER', 'HIUSER']
namesSectPointer = pointer + size * (elfSectionHeaderTableEntryCount - 1)
#print(elfData[elfSectionOffset:elfSectionOffset + size])
section = struct.unpack(
    elfSectionTemplate, elfData[namesSectPointer:namesSectPointer + size])
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

templ = sectionSize * 'c'
stra = struct.unpack(
    templ, elfData[sectionOffset:sectionOffset + sectionSize])
names = ''
for i in range(len(stra)):
    if stra[i] == b"\x00":
        names += "$"
    else:
        names += stra[i].decode('utf-8', 'backslashreplace')
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
    if sectionType > len(types):
        type = 'LOOS'
    else:
        type = types[sectionType]
    name = ''
    k = sectionName
    while names[k] != '$':
        name += names[k]
        k += 1
    if name == '.dynstr':
        print('-------Task 4--------')
        namesx = ''
        templx = sectionSize * 'c'
        print(hex(sectionOffset))
        print(sectionSize)
        strax = struct.unpack(templx, elfData[sectionOffset:sectionOffset + sectionSize])
        print(strax)
        for j in range(len(strax)):
            if strax[j] == b"\x00":
                print(namesx)
                namesx = ''
            else:
                namesx += strax[j].decode('utf-8', 'backslashreplace')

print('--------------------------')
print()
print()











print('-------TASK-5----------')
macho = 'ip.so'
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




print('-------TASK-8----------')
machoLoadCommandTemplate = '2I'
machoSegmentTemplate = '2I16c4Q2i2I'
machoSectionTemplate = '16c16c2Q8I'
for i in range(machoNumberCommands):
    CurrentLoadCommand = struct.unpack(machoLoadCommandTemplate, machoData[currentPoint:currentPoint + 8])
    CurrentLoadCommandType = CurrentLoadCommand[0]
    CurrentLoadCommandSize = CurrentLoadCommand[1]
    #print(hex(CurrentLoadCommandType), hex(CurrentLoadCommandSize))
    #print(hex(CurrentLoadCommandType))
    if CurrentLoadCommandType == 0x2:
        dynamicTemplate = '6I'
        cmd = struct.unpack(dynamicTemplate, machoData[currentPoint:currentPoint + 24])
        cmdType = cmd[0]
        cmdSize = cmd[1]
        cmdSymOff = cmd[2]
        cmdNSyms = cmd[3]
        cmdStrOff = cmd[4]
        cmdStrSize = cmd[5]
        list = struct.unpack(cmdStrSize * 'c', machoData[cmdStrOff:cmdStrOff + cmdStrSize])
        #print(list)
        sym = ''
        for k in range(cmdStrSize):
            if list[k] == b"\x00":
                print(sym)
                sym = ''
            else:
                sym += list[k].decode('utf-8', 'backslashreplace')
        #print(sym)
        #cmdTime = cmd[]
        #print(path)

    currentPoint += CurrentLoadCommandSize
print('-----------------------')
print()
print()
