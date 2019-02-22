<?
// file pedef is used to define some structures of portable executable files

/*
#define IMAGE_DOS_SIGNATURE                 0x4D5A      // MZ
#define IMAGE_OS2_SIGNATURE                 0x4E45      // NE
#define IMAGE_OS2_SIGNATURE_LE              0x4C45      // LE
#define IMAGE_NT_SIGNATURE                  0x50450000      // PE
#endif

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

*/

define("IMAGE_DOS_SIGNATURE",0x5A4D);
define("IMAGE_OS2_SIGNATURE",0x4E45);
define("IMAGE_OS2_SIGNATURE_LE",0x4C45);
define("IMAGE_NT_SIGNATURE",0x50450000);

define("IMAGE_DOS_HEADER_LEN",64);

define("IMAGE_DOS_HEADER","ve_magic/Se_cblp/Se_cp/Se_crlc/Se_cparhdr/Se_minalloc/Se_maxalloc/Se_ss/Se_sp/Se_csum/Se_ip/Se_cs/Se_lfarlc/Se_ovno/S4e_res/Se_oemid/Se_oeminfo/S10e_res2/Se_lfanew");
define("IMAGE_DOS_HEADER_PACK","vSSSSSSSSSSSSSS4SSS10S");


/*
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/

define("IMAGE_FILE_HEADER_LEN", 20);

define("IMAGE_FILE_HEADER","SMachine/SNumberOfSections/LTimeDateStamp/LPointerToSymbolTable/LNumberOfSymbols/SSizeOfOptionalHeader/SCharacteristics");



/*
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;

    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;

    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;

    WORD    Subsystem;
    WORD    DllCharacteristics;

    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;

    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
*/

// for the last item:  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES], it contains 128 bytes


define("CertificateTableIndex",4);

define("IMAGE_NUMBEROF_DIRECTORY_ENTRIES",16);

define("IMAGE_DATA_DIRECTORY_LEN",8);
define("IMAGE_DATA_DIRECTORY","LVirtualAddress/LSize");
define("IMAGE_DATA_DIRECTORY_PACK","LL");

define("IMAGE_OPTIONAL_HEADER32_LEN",224);

define("IMAGE_OPTIONAL_HEADER32","SMagic/CMajorLinkerVersion/CMinorLinkerVersion/LSizeOfCode/LSizeOfInitializedData/LSizeOfUninitializedData/LAddressOfEntryPoint/LBaseOfCode/LBaseOfData/LImageBase/LSectionAlignment/LFileAlignment/SMajorOperatingSystemVersion/SMinorOperatingSystemVersion/SMajorImageVersion/SMinorImageVersion/SMajorSubsystemVersion/SMinorSubsystemVersion/LWin32VersionValue/LSizeOfImage/LSizeOfHeaders/LCheckSum/SSubsystem/SDllCharacteristics/LSizeOfStackReserve/LSizeOfStackCommit/LSizeOfHeapReserve/LSizeOfHeapCommit/LLoaderFlags/LNumberOfRvaAndSizes/a128DataDirectory");

define("IMAGE_OPTIONAL_HEADER32_PACK","SCCLLLLLLLLLSSSSSSLLLLSSLLLLLLa128");


/*
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
*/
define("IMAGE_OPTIONAL_HEADER64_LEN",240);

define("IMAGE_OPTIONAL_HEADER64","SMagic/CMajorLinkerVersion/CMinorLinkerVersion/LSizeOfCode/LSizeOfInitializedData/LSizeOfUninitializedData/LAddressOfEntryPoint/LBaseOfCode/QImageBase/LSectionAlignment/LFileAlignment/SMajorOperatingSystemVersion/SMinorOperatingSystemVersion/SMajorImageVersion/SMinorImageVersion/SMajorSubsystemVersion/SMinorSubsystemVersion/LWin32VersionValue/LSizeOfImage/LSizeOfHeaders/LCheckSum/SSubsystem/SDllCharacteristics/QSizeOfStackReserve/QSizeOfStackCommit/QSizeOfHeapReserve/QSizeOfHeapCommit/LLoaderFlags/LNumberOfRvaAndSizes/a128DataDirectory");

define("IMAGE_OPTIONAL_HEADER64_PACK","SCCLLLLLQLLSSSSSSLLLLSSQQQQLLa128");
/*
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
*/
define("IMAGE_NT_HEADERS64","NSignature/a".IMAGE_FILE_HEADER_LEN."FileHeader/a".IMAGE_OPTIONAL_HEADER64_LEN."OptionalHeader");
define("IMAGE_NT_HEADERS64_LEN",264);
define("IMAGE_NT_HEADERS64_PACK","Na".IMAGE_FILE_HEADER_LEN."a".IMAGE_OPTIONAL_HEADER64_LEN);


/*
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
*/

define("IMAGE_NT_HEADERS32","NSignature/a".IMAGE_FILE_HEADER_LEN."FileHeader/a".IMAGE_OPTIONAL_HEADER32_LEN."OptionalHeader");
define("IMAGE_NT_HEADERS32_LEN",248);

define("IMAGE_NT_HEADERS32_PACK","Na".IMAGE_FILE_HEADER_LEN."a".IMAGE_OPTIONAL_HEADER32_LEN);

function GET_SIZE_PAGE($n)  
{

	return ( (($n)%4096) ? (floor(($n)/4096)+1)*4096 : ($n) );
}


define("IMAGE_FILE_MACHINE_AMD64",0x8664);   // AMD64 (K8)
define("IMAGE_FILE_MACHINE_I386", 0x014c);  // Intel 386.
?>