// NOTE(chuck): Parse the contents of a portable executable.
#include <stdio.h>
#include <windows.h>

static char Memory[1024 * 1024 * 64];
#define ArrayCount(Array) (sizeof(Array)/(sizeof((Array)[0])))
typedef int b32;

struct dos_header
{
    char MZ[2];
    unsigned short Garbage[29];
    unsigned long PEAddress;
};

struct pe_header
{
    unsigned short Machine;
    unsigned short SectionCount;
    unsigned long  Timestamp;
    unsigned long  SymbolTablePointer;
    unsigned long  SymbolCount;
    unsigned short OptionalHeaderLength;
    unsigned short Characteristics;
};

struct pe_directory
{
    unsigned long VirtualAddress;
    unsigned long Size;    
};

// NOTE(chuck): All versions are in Major + Minor order.
struct pe_optional_header32
{
    unsigned short Magic;
    unsigned char  LinkerVersion[2];
    unsigned long  CodeLength;
    unsigned long  InitializedDataLength;
    unsigned long  UninitializedDataLength;
    unsigned long  EntryPointAddress;
    unsigned long  CodeAddress;
    unsigned long  DataAddress;
    unsigned long  ImageAddress;
    unsigned long  SectionAligment;
    unsigned long  FileAlignment;
    unsigned short OSVersion[2];
    unsigned short ImageVersion[2];
    unsigned short SubsystemVersion[2];
    unsigned long  Reserved;
    unsigned long  ImageLength;
    unsigned long  HeadersLength;
    unsigned long  Checksum;
    unsigned short Subsystem;
    unsigned short DLLCharacteristics;
    unsigned long  StackReserveLength;
    unsigned long  StackCommitLength;
    unsigned long  HeapReserveLength;
    unsigned long  HeapCommitLength;
    unsigned long  LoaderFlags; // NOTE(chuck): Obsolete
    unsigned long  DirectoryCount;
    struct pe_directory   Directory[16];
};

struct pe_optional_header64
{
    unsigned short Magic;
    unsigned char  LinkerVersion[2];
    unsigned long  CodeLength;
    unsigned long  InitializedDataLength;
    unsigned long  UninitializedDataLength;
    unsigned long  EntryPointAddress;
    unsigned long  CodeAddress;
    // unsigned long  DataAddress; // NOTE(chuck): 64-bit does not have a data address.
    unsigned long long ImageAddress; // NOTE(chuck): 64-bit
    unsigned long  SectionAligment;
    unsigned long  FileAlignment;
    unsigned short OSVersion[2];
    unsigned short ImageVersion[2];
    unsigned short SubsystemVersion[2];
    unsigned long  Reserved;
    unsigned long  ImageLength;
    unsigned long  HeadersLength;
    unsigned long  Checksum;
    unsigned short Subsystem;
    unsigned short DLLCharacteristics;
    unsigned long long StackReserveLength;// NOTE(chuck): 64-bit
    unsigned long long StackCommitLength;// NOTE(chuck): 64-bit
    unsigned long long HeapReserveLength; // NOTE(chuck): 64-bit
    unsigned long long HeapCommitLength; // NOTE(chuck): 64-bit
    unsigned long  LoaderFlags; // NOTE(chuck): Obsolete
    unsigned long  DirectoryCount;
    struct pe_directory   Directory[16];
};

struct pe_section_header
{
    unsigned char  Name[8];
    unsigned long  VirtualSize;
    unsigned long  VirtualAddress;
    unsigned long  RawLength;
    unsigned long  RawAddress;
    unsigned long  RelocationAddress;
    unsigned long  LineNumberAddress;
    unsigned short RelocationCount;
    unsigned short LineNumberCount;
    unsigned long  Characteristics;
};

struct bit_flag
{
    unsigned long Bits;
    char *Description;
};

struct pe_import
{
    unsigned long OriginalFirstHunk;
    unsigned long Timestamp;
    unsigned long ForwarderChain;
    unsigned long Name;
    unsigned long FirstThunk;
};

static void
PrintBitFlags(unsigned long Value, struct bit_flag *Flags, int FlagCount, int Indent, int HexWidthSpecifier)
{
    for(int Index = 0;
        Index < FlagCount;
        ++Index)
    {
        struct bit_flag *Flag = Flags + Index;
        if(Value & Flag->Bits)
        {
            printf("%*s0x%.*x %s\n", Indent, " ", HexWidthSpecifier, Flag->Bits, Flag->Description);
        }
    }
}

static void
PrintSubsystem(int Subsystem)
{
    printf("Subsystem\n");
    switch(Subsystem)
    {
        case  0: printf("   0 Unknown subsystem.\n"); break;
        case  1: printf("   1 No subsystem required (device drivers and native system processes).\n"); break;
        case  2: printf("   2 Windows graphical user interface (GUI) subsystem.\n"); break;
        case  3: printf("   3 Windows character-mode user interface (CUI) subsystem.\n"); break;
        case  5: printf("   5 OS/2 CUI subsystem.\n"); break;
        case  7: printf("   7 POSIX CUI subsystem.\n"); break;
        case  9: printf("   9 Windows CE system.\n"); break;
        case 10: printf("  10 Extensible Firmware Interface (EFI) application.\n"); break;
        case 11: printf("  11 EFI driver with boot services.\n"); break;
        case 12: printf("  12 EFI driver with run-time services.\n"); break;
        case 13: printf("  13 EFI ROM image.\n"); break;
        case 14: printf("  14 Xbox system.\n"); break;
        case 16: printf("  16 Boot application.\n"); break;
    }
}

static void
PrintDLLCharacteristics(int DLLCharacteristics)
{
    if(DLLCharacteristics)
    {
        printf("DLL characteristics\n");
        struct bit_flag DLLCharacteristicBitFlags[] =
        {
            {0x0001, "Reserved."},
            {0x0002, "Reserved."},
            {0x0004, "Reserved."},
            {0x0008, "Reserved."},
            {0x0020, "ASLR with 64 bit address space."},
            {0x0040, "The DLL can be relocated at load time."},
            {0x0080, "Code integrity checks are forced. If you set this flag and a section contains only uninitialized data, set the PointerToRawData member of IMAGE_SECTION_HEADER for that section to zero; otherwise, the image will fail to load because the digital signature cannot be verified."},
            {0x0100, "The image is compatible with data execution prevention (DEP)."},
            {0x0200, "The image is isolation aware, but should not be isolated."},
            {0x0400, "The image does not use structured exception handling (SEH). No handlers can be called in this image."},
            {0x0800, "Do not bind the image."},
            {0x1000, "Image should execute in an AppContainer."},
            {0x2000, "A WDM driver."},
            {0x4000, "Image supports Control Flow Guard."},
            {0x8000, "The image is terminal server aware."},
        };
        PrintBitFlags(DLLCharacteristics, DLLCharacteristicBitFlags, ArrayCount(DLLCharacteristicBitFlags), 2, 4);
    }
}

static void
PrintDirectories(int DirectoryCount, struct pe_directory *DirectoryList)
{
    printf("Directory count %d\n", DirectoryCount);
    char *DirectoryDescriptor[] =
    {
        "Export table",
        "Import table",
        "Resource table",
        "Exception table",
        "Certificate table",
        "Base relocation table",
        "Debug info",
        "Architecture-specific data",
        "Global pointer register",
        "Thread local storage table",
        "Load configuration table",
        "Bound import table",
        "Import address table",
        "Delay import descriptor",
        "CLR header",
        "Reserved",
    };
    for(int DirectoryIndex = 0;
        DirectoryIndex < ArrayCount(DirectoryList);
        ++DirectoryIndex)
    {
        struct pe_directory *Directory = DirectoryList + DirectoryIndex;
        printf("  (%02d) %27s: Virtual address 0x%08x, %d bytes\n",
            DirectoryIndex, DirectoryDescriptor[DirectoryIndex],
            Directory->VirtualAddress, Directory->Size);
    }
}

#define PrintSharedHeaderInfo(PEOptionalHeader) \
    printf("   Linker version %d.%d\n", PEOptionalHeader->LinkerVersion[0], PEOptionalHeader->LinkerVersion[1]); \
    printf("       OS version %d.%d\n", PEOptionalHeader->OSVersion[0], PEOptionalHeader->OSVersion[1]); \
    printf("    Image version %d.%d\n", PEOptionalHeader->ImageVersion[0], PEOptionalHeader->ImageVersion[1]); \
    printf("Subsystem version %d.%d\n", PEOptionalHeader->SubsystemVersion[0], PEOptionalHeader->SubsystemVersion[1]); \
    printf("Section alignment %d\n", PEOptionalHeader->SectionAligment); \
    printf("   File alignment %d\n", PEOptionalHeader->FileAlignment); \
    printf("         Checksum 0x%08x\n", PEOptionalHeader->Checksum); \
    printf("        Code size %d bytes\n", PEOptionalHeader->CodeLength); \
    printf("   Init data size %d bytes\n", PEOptionalHeader->InitializedDataLength); \
    printf(" Uninit data size %d bytes\n", PEOptionalHeader->UninitializedDataLength); \
    printf("       Image size %d bytes\n", PEOptionalHeader->ImageLength); \
    printf("     Headers size %d bytes\n", PEOptionalHeader->HeadersLength); \
    printf("   Stack reserved %lld bytes\n", (unsigned long long)PEOptionalHeader->StackReserveLength); \
    printf("   Stack   commit %lld bytes\n", (unsigned long long)PEOptionalHeader->StackCommitLength); \
    printf("    Heap reserved %lld bytes\n", (unsigned long long)PEOptionalHeader->HeapReserveLength); \
    printf("    Heap   commit %lld bytes\n", (unsigned long long)PEOptionalHeader->HeapCommitLength); \
    printf("            Entry 0x%08x\n", PEOptionalHeader->EntryPointAddress); \
    printf("             Code 0x%08x\n", PEOptionalHeader->CodeAddress); \
    printf("            Image 0x%016llx\n", (unsigned long long)PEOptionalHeader->ImageAddress);

int main(int ArgCount, char **Args)
{
    int Result = 0;

    if(ArgCount != 2)
    {
        fprintf(stderr, "Usage: parse_pe <program.exe>\n");
        Result = 1;
    }
    else
    {
        char *EXEFilename = Args[1];
        HANDLE FileHandle = CreateFileA(EXEFilename, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        if(FileHandle != INVALID_HANDLE_VALUE)
        {
            DWORD BytesRead;
            if(ReadFile(FileHandle, Memory, sizeof(Memory), &BytesRead, 0))
            {
                struct dos_header *DOSHeader = (struct dos_header *)Memory;
                if((DOSHeader->MZ[0] == 'M') &&
                   (DOSHeader->MZ[1] == 'Z'))
                {
                    char *PE = Memory + DOSHeader->PEAddress;
                    if((PE[0] == 'P') &&
                       (PE[1] == 'E') &&
                       (PE[2] == 0) &&
                       (PE[3] == 0))
                    {
                        printf("PE signature offset: 0x%x\n", DOSHeader->PEAddress);
                        struct pe_header *PEHeader = (struct pe_header *)(PE + 4);

                        printf("Machine 0x%4d ", PEHeader->Machine);
                        switch(PEHeader->Machine)
                        {
                            case 0x014c: printf("Intel 386 or later processors and compatible processors\n"); break;
                            case 0x0160: printf("MIPS big endian\n"); break;
                            case 0x0162: printf("MIPS little endian\n"); break;
                            case 0x0166: printf("MIPS little endian R4000\n"); break;
                            case 0x0168: printf("MIPS little endian R10000\n"); break;
                            case 0x0169: printf("MIPS little endian WCE v2\n"); break;
                            case 0x0184: printf("Alpha_AXP\n"); break;
                            case 0x01a2: printf("Hitachi SH3 little endian\n"); break;
                            case 0x01a3: printf("Hitachi SH3 DSP\n"); break;
                            case 0x01a4: printf("SH3E little endian\n"); break;
                            case 0x01a6: printf("Hitachi SH4\n"); break;
                            case 0x01a8: printf("Hitachi SH5\n"); break;
                            case 0x01c0: printf("ARM little endian\n"); break;
                            case 0x01c2: printf("ARM or Thumb ('interworking') little endian\n"); break;
                            case 0x01c4: printf("ARM Thumb-2 little endian\n"); break;
                            case 0x01d3: printf("Matsushita AM33\n"); break;
                            case 0x01f0: printf("Power PC little endian\n"); break;
                            case 0x01f1: printf("Power PC with floating point support\n"); break;
                            case 0x0200: printf("Intel Itanium processor family\n"); break;
                            case 0x0266: printf("MIPS16\n"); break;
                            case 0x0284: printf("ALPHA64\n"); break;
                            case 0x0366: printf("MIPS with FPU\n"); break;
                            case 0x0466: printf("MIPS16 with FPU\n"); break;
                            case 0x0520: printf("Infineon\n"); break;
                            case 0x0cef: printf("CEF\n"); break;
                            case 0x0ebc: printf("EFI byte code\n"); break;
                            case 0x5032: printf("RISC-V 32-bit address space\n"); break;
                            case 0x5064: printf("RISC-V 64-bit address space\n"); break;
                            case 0x5128: printf("RISC-V 128-bit address space\n"); break;
                            case 0x8664: printf("x64\n"); break;
                            case 0x9041: printf("Mitsubishi M32R little endian\n"); break;
                            case 0xaa64: printf("ARM64 little endian\n"); break;
                            default: printf("Unknown\n"); break;
                        }

                        printf("Timestamp %u\n", PEHeader->Timestamp);
                        printf("Symbol table 0x%x\n", PEHeader->SymbolTablePointer);
                        printf("Symbol count %d\n", PEHeader->SymbolCount);
                        printf("Optional header length %d\n", PEHeader->OptionalHeaderLength);

                        printf("Characteristics\n");
                        struct bit_flag PEHeaderCharacteristics[] =
                        {
                            {0x0001, "Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error."},
                            {0x0002, "The file is executable (there are no unresolved external references)."},
                            {0x0004, "COFF line numbers were stripped from the file."},
                            {0x0008, "COFF symbol table entries were stripped from file."},
                            {0x0010, "Aggressively trim the working set. This value is obsolete."},
                            {0x0020, "The application can handle addresses larger than 2 GB."},
                            {0x0080, "The bytes of the word are reversed. This flag is obsolete."},
                            {0x0100, "The computer supports 32-bit words."},
                            {0x0200, "Debugging information was removed and stored separately in another file."},
                            {0x0400, "If the image is on removable media, copy it to and run it from the swap file."},
                            {0x0800, "If the image is on the network, copy it to and run it from the swap file."},
                            {0x1000, "The image is a system file."},
                            {0x2000, "The image is a DLL file. While it is an executable file, it cannot be run directly."},
                            {0x4000, "The file should be run only on a uniprocessor computer."},
                            {0x8000, "The bytes of the word are reversed. This flag is obsolete."},
                        };
                        PrintBitFlags(PEHeader->Characteristics, PEHeaderCharacteristics, ArrayCount(PEHeaderCharacteristics), 2, 4);

                        struct pe_directory *ImportTable = 0;
                        char *PEOptionalHeaderStart = (char *)PEHeader + sizeof(struct pe_header);
                        b32 Is64Bit = (PEHeader->OptionalHeaderLength == sizeof(struct pe_optional_header64));
                        if(Is64Bit)
                        {
                            struct pe_optional_header64 *PEOptionalHeader = (struct pe_optional_header64 *)PEOptionalHeaderStart;
                            ImportTable = PEOptionalHeader->Directory + 1;

                            PrintSharedHeaderInfo(PEOptionalHeader);
                            PrintSubsystem(PEOptionalHeader->Subsystem);
                            PrintDLLCharacteristics(PEOptionalHeader->DLLCharacteristics);
                            PrintDirectories(PEOptionalHeader->DirectoryCount, PEOptionalHeader->Directory);
                        }
                        else
                        {
                            struct pe_optional_header32 *PEOptionalHeader = (struct pe_optional_header32 *)PEOptionalHeaderStart;
                            ImportTable = PEOptionalHeader->Directory + 1;

                            PrintSharedHeaderInfo(PEOptionalHeader);
                            printf("             Data 0x%08x\n", PEOptionalHeader->DataAddress); // NOTE(chuck): Data address is specific to 32-bit.
                            PrintSubsystem(PEOptionalHeader->Subsystem);
                            PrintDLLCharacteristics(PEOptionalHeader->DLLCharacteristics);
                            PrintDirectories(PEOptionalHeader->DirectoryCount, PEOptionalHeader->Directory);
                        }
                            

                        if(PEHeader->SectionCount)
                        {
                            printf("%d section%s\n", PEHeader->SectionCount, (PEHeader->SectionCount == 1) ? "" : "s");
                            struct bit_flag PESectionHeaderCharacteristics[] = 
                            {
                                {0x00000000, "Reserved."},
                                {0x00000001, "Reserved."},
                                {0x00000002, "Reserved."},
                                {0x00000004, "Reserved."},
                                {0x00000008, "The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES."},
                                {0x00000010, "Reserved."},
                                {0x00000020, "The section contains executable code."},
                                {0x00000040, "The section contains initialized data."},
                                {0x00000080, "The section contains uninitialized data."},
                                {0x00000100, "Reserved."},
                                {0x00000200, "The section contains comments or other information. This is valid only for object files."},
                                {0x00000400, "Reserved."},
                                {0x00000800, "The section will not become part of the image. This is valid only for object files."},
                                {0x00001000, "The section contains COMDAT data. This is valid only for object files."},
                                {0x00002000, "Reserved."},
                                {0x00004000, "Reset speculative exceptions handling bits in the TLB entries for this section."},
                                {0x00008000, "The section contains data referenced through the global pointer."},
                                {0x00010000, "Reserved."},
                                {0x00020000, "Reserved."},
                                {0x00040000, "Reserved."},
                                {0x00080000, "Reserved."},
                                {0x00100000, "Align data on a 1-byte boundary. This is valid only for object files."},
                                {0x00200000, "Align data on a 2-byte boundary. This is valid only for object files."},
                                {0x00300000, "Align data on a 4-byte boundary. This is valid only for object files."},
                                {0x00400000, "Align data on a 8-byte boundary. This is valid only for object files."},
                                {0x00500000, "Align data on a 16-byte boundary. This is valid only for object files."},
                                {0x00600000, "Align data on a 32-byte boundary. This is valid only for object files."},
                                {0x00700000, "Align data on a 64-byte boundary. This is valid only for object files."},
                                {0x00800000, "Align data on a 128-byte boundary. This is valid only for object files."},
                                {0x00900000, "Align data on a 256-byte boundary. This is valid only for object files."},
                                {0x00A00000, "Align data on a 512-byte boundary. This is valid only for object files."},
                                {0x00B00000, "Align data on a 1024-byte boundary. This is valid only for object files."},
                                {0x00C00000, "Align data on a 2048-byte boundary. This is valid only for object files."},
                                {0x00D00000, "Align data on a 4096-byte boundary. This is valid only for object files."},
                                {0x00E00000, "Align data on a 8192-byte boundary. This is valid only for object files."},
                                {0x01000000, "The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section."},
                                {0x02000000, "The section can be discarded as needed."},
                                {0x04000000, "The section cannot be cached."},
                                {0x08000000, "The section cannot be paged."},
                                {0x10000000, "The section can be shared in memory."},
                                {0x20000000, "The section can be executed as code."},
                                {0x40000000, "The section can be read."},
                                {0x80000000, "The section can be written to."},
                            };

                            printf("Import table virtual address 0x%08x\n", ImportTable->VirtualAddress);

                            // NOTE(chuck): Optional header size varies!  I've seen 224 and 240 byte lengths;
                            struct pe_section_header *ImportSection = 0;
                            struct pe_section_header *PESectionHeader = (struct pe_section_header *)(PEOptionalHeaderStart + PEHeader->OptionalHeaderLength);
                            for(int SectionIndex = 0;
                                SectionIndex < PEHeader->SectionCount;
                                ++SectionIndex, ++PESectionHeader)
                            {
                                printf("  (%02d) %8.*s: Virtual address 0x%08x, Raw address 0x%08x, Raw bytes %d\n", SectionIndex, 8,
                                       PESectionHeader->Name, PESectionHeader->VirtualAddress, PESectionHeader->RawAddress,
                                       PESectionHeader->RawLength);
                                if(PESectionHeader->RelocationCount)
                                {
                                    printf("                 Relocations  (%d) 0x%08x\n",
                                           PESectionHeader->RelocationCount, PESectionHeader->RelocationAddress);
                                }
                                if(PESectionHeader->LineNumberCount)
                                {
                                    printf("                 Line numbers (%d) 0x%08x\n",
                                           PESectionHeader->LineNumberCount, PESectionHeader->LineNumberAddress);
                                }
                                
                                if(PESectionHeader->Characteristics)
                                {
                                    printf("    Characteristics\n");
                                    PrintBitFlags(PESectionHeader->Characteristics, PESectionHeaderCharacteristics,
                                                  ArrayCount(PESectionHeaderCharacteristics), 6, 8);
                                    printf("\n");
                                }

                                unsigned long ImportVirtualAddress = ImportTable->VirtualAddress;
                                if((ImportVirtualAddress >= PESectionHeader->VirtualAddress) &&
                                    (ImportVirtualAddress < (PESectionHeader->VirtualAddress + PESectionHeader->VirtualSize)))
                                {
                                    ImportSection = PESectionHeader;
                                }
                            }

                            if(ImportSection)
                            {
                                printf("DLL imports\n");
                                char *RawOffset = Memory + ImportSection->RawAddress;
                                for(struct pe_import *Import = (struct pe_import *)(RawOffset + (ImportTable->VirtualAddress - ImportSection->VirtualAddress));
                                    Import->Name;
                                    ++Import)
                                {
                                    printf("  %s\n", RawOffset + (Import->Name - ImportSection->VirtualAddress));
                                    unsigned long Thunk = Import->OriginalFirstHunk;
                                    if(!Thunk)
                                    {
                                        Thunk = Import->FirstThunk;
                                    }
                                    if(Is64Bit)
                                    {
                                        for(unsigned long long *ThunkData = (unsigned long long *)(RawOffset + (Thunk - ImportSection->VirtualAddress));
                                            *ThunkData;
                                            ++ThunkData)
                                        {
                                            printf("    %s\n", RawOffset + (*ThunkData - ImportSection->VirtualAddress + 2));
                                        }
                                    }
                                    else
                                    {
                                        for(unsigned long *ThunkData = (unsigned long *)(RawOffset + (Thunk - ImportSection->VirtualAddress));
                                            *ThunkData;
                                            ++ThunkData)
                                        {
                                            printf("    %s\n", RawOffset + (*ThunkData - ImportSection->VirtualAddress + 2));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        fprintf(stderr, "This is not a valid portable executable file.  The PE signature is invalid.\n");
                        Result = 1;
                    }
                }
                else
                {
                    fprintf(stderr, "This is not a valid portable executable file.  The MZ signature is invalid.\n");
                    Result = 1;
                }
            }
            else
            {
                fprintf(stderr, "There was a problem reading the file.\n");
                Result = 1;
            }
        }
        else
        {
            fprintf(stderr, "The file could not be opened.\n");
            Result = 1;
        }
    }
    
    return(Result);
}