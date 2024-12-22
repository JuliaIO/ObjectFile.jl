# These constants are in glibc and llvm:
# * https://github.com/bminor/glibc/blob/969d7cf89966d55fbf0732ae7bc0949a970c837d/elf/elf.h
# * https://github.com/llvm/llvm-project/blob/b2d7312d52f299a2f854c673796ad1a699e0d79f/llvm/include/llvm/BinaryFormat/ELF.h

# e_ident[EIBCLASS]
const ELFCLASSNONE = 0 #Invalid class
const ELFCLASS32 = 1 #32-bit objects
const ELFCLASS64 = 2 #64-bit objects

# e_ident[EI_DATA]
const ELFDATANONE = 0
const ELFDATA2LSB = 1
const ELFDATA2MSB = 2

# e_ident[EI_VERSION]
const EV_NONE = 0       #Invalid Version
const EV_CURRENT = 1    #Current Version

# e_ident[EI_OSABI]
const ELFOSABI_NONE         = 0   # No extensions or unspecified
const ELFOSABI_HPUX         = 1   # Hewlett-Packard HP-UX
const ELFOSABI_NETBSD       = 2   # NetBSD
const ELFOSABI_GNU          = 3   # GNU
const ELFOSABI_LINUX        = 3   # Linux historical - alias for ELFOSABI_GNU
const ELFOSABI_SOLARIS      = 6   # Sun Solaris
const ELFOSABI_AIX          = 7   # AIX
const ELFOSABI_IRIX         = 8   # IRIX
const ELFOSABI_FREEBSD      = 9   # FreeBSD
const ELFOSABI_TRU64        = 10  # Compaq TRU64 UNIX
const ELFOSABI_MODESTO      = 11  # Novell Modesto
const ELFOSABI_OPENBSD      = 12  # Open BSD
const ELFOSABI_OPENVMS      = 13  # Open VMS
const ELFOSABI_NSK          = 14  # Hewlett-Packard Non-Stop Kernel
const ELFOSABI_AROS         = 15  # Amiga Research OS
const ELFOSABI_FENIXOS      = 16  # FenixOS
const ELFOSABI_CLOUDABI     = 17  # Nuxi CloudABI
const ELFOSABI_OPENVOS      = 18  # Stratus Technologies OpenVOS
const ELFOSABI_C6000_ELFABI = 64  # Bare-metal TMS320C6000
const ELFOSABI_C6000_LINUX  = 65  # Linux TMS320C6000
const ELFOSABI_ARM	        = 97  # ARM
const ELFOSABI_STANDALONE   = 255 # Standalone (embedded) application

# e_type constants
@constants ET_TYPES "ET_" begin
    const ET_NONE = 0   #No file type
    const ET_REL  = 1   #Relocatable file
    const ET_EXEC = 2   #Executable file
    const ET_DYN  = 3   #Shared object file
    const ET_CORE = 4   #Core file
end
@constants ET_RANGES "ET_" begin
    const ET_LOOS       = 0xfe00  #Operating system-specific
    const ET_HIOS       = 0xfeff  #Operating system-specific
    const ET_LOPROC     = 0xff00  #Processor-specific
    const ET_HIPROC     = 0xffff  #Processor-specific
end

@constants EM_MACHINES "EM_" begin
    # e_machine constants
    const EM_NONE = 0   #No machine
    const EM_M32  = 1   #AT&T WE 32100
    const EM_SPARC    = 2   #SPARC
    const EM_386  = 3   #Intel 80386
    const EM_68K  = 4   #Motorola 68000
    const EM_88K  = 5   #Motorola 88000
    #6                  Reserved for future use (was EM_486)
    const EM_860  = 7   #Intel 80860
    const EM_MIPS = 8   #MIPS I Architecture
    const EM_S370 = 9   #IBM System/370 Processor
    const EM_MIPS_RS3_LE  = 10  #MIPS RS3000 Little-endian
    #11-14              Reserved for future use
    const EM_PARISC   = 15  #Hewlett-Packard PA-RISC
    #16  Reserved for future use
    const EM_VPP500   = 17  #Fujitsu VPP500
    const EM_SPARC32PLUS  = 18  #Enhanced instruction set SPARC
    const EM_960  = 19  #Intel 80960
    const EM_PPC  = 20  #PowerPC
    const EM_PPC64    = 21  #64-bit PowerPC
    const EM_S390 = 22  #IBM System/390 Processor
    const EM_SPU  = 23  #IBM SPU/SPC
    #24-35   Reserved for future use
    const EM_V800 = 36  #NEC V800
    const EM_FR20 = 37  #Fujitsu FR20
    const EM_RH32 = 38  #TRW RH-32
    const EM_RCE  = 39  #Motorola RCE
    const EM_ARM  = 40  #ARM 32-bit architecture (AARCH32)
    const EM_ALPHA    = 41  #Digital Alpha
    const EM_SH   = 42  #Hitachi SH
    const EM_SPARCV9  = 43  #SPARC Version 9
    const EM_TRICORE  = 44  #Siemens TriCore embedded processor
    const EM_ARC  = 45  #Argonaut RISC Core, Argonaut Technologies Inc.
    const EM_H8_300   = 46  #Hitachi H8/300
    const EM_H8_300H  = 47  #Hitachi H8/300H
    const EM_H8S  = 48  #Hitachi H8S
    const EM_H8_500   = 49  #Hitachi H8/500
    const EM_IA_64    = 50  #Intel IA-64 processor architecture
    const EM_MIPS_X   = 51  #Stanford MIPS-X
    const EM_COLDFIRE = 52  #Motorola ColdFire
    const EM_68HC12   = 53  #Motorola M68HC12
    const EM_MMA  = 54  #Fujitsu MMA Multimedia Accelerator
    const EM_PCP  = 55  #Siemens PCP
    const EM_NCPU = 56  #Sony nCPU embedded RISC processor
    const EM_NDR1 = 57  #Denso NDR1 microprocessor
    const EM_STARCORE = 58  #Motorola Star*Core processor
    const EM_ME16 = 59  #Toyota ME16 processor
    const EM_ST100    = 60  #STMicroelectronics ST100 processor
    const EM_TINYJ    = 61  #Advanced Logic Corp. TinyJ embedded processor family
    const EM_X86_64   = 62  #AMD x86-64 architecture
    const EM_PDSP = 63  #Sony DSP Processor
    const EM_PDP10    = 64  #Digital Equipment Corp. PDP-10
    const EM_PDP11    = 65  #Digital Equipment Corp. PDP-11
    const EM_FX66 = 66  #Siemens FX66 microcontroller
    const EM_ST9PLUS  = 67  #STMicroelectronics ST9+ 8/16 bit microcontroller
    const EM_ST7  = 68  #STMicroelectronics ST7 8-bit microcontroller
    const EM_68HC16   = 69  #Motorola MC68HC16 Microcontroller
    const EM_68HC11   = 70  #Motorola MC68HC11 Microcontroller
    const EM_68HC08   = 71  #Motorola MC68HC08 Microcontroller
    const EM_68HC05   = 72  #Motorola MC68HC05 Microcontroller
    const EM_SVX  = 73  #Silicon Graphics SVx
    const EM_ST19 = 74  #STMicroelectronics ST19 8-bit microcontroller
    const EM_VAX  = 75  #Digital VAX
    const EM_CRIS = 76  #Axis Communications 32-bit embedded processor
    const EM_JAVELIN  = 77  #Infineon Technologies 32-bit embedded processor
    const EM_FIREPATH = 78  #Element 14 64-bit DSP Processor
    const EM_ZSP  = 79  #LSI Logic 16-bit DSP Processor
    const EM_MMIX = 80  #Donald Knuth's educational 64-bit processor
    const EM_HUANY    = 81  #Harvard University machine-independent object files
    const EM_PRISM    = 82  #SiTera Prism
    const EM_AVR  = 83  #Atmel AVR 8-bit microcontroller
    const EM_FR30 = 84  #Fujitsu FR30
    const EM_D10V = 85  #Mitsubishi D10V
    const EM_D30V = 86  #Mitsubishi D30V
    const EM_V850 = 87  #NEC v850
    const EM_M32R = 88  #Mitsubishi M32R
    const EM_MN10300  = 89  #Matsushita MN10300
    const EM_MN10200  = 90  #Matsushita MN10200
    const EM_PJ   = 91  #picoJava
    const EM_OPENRISC = 92  #OpenRISC 32-bit embedded processor
    const EM_ARC_COMPACT  = 93  #ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
    const EM_XTENSA   = 94  #Tensilica Xtensa Architecture
    const EM_VIDEOCORE    = 95  #Alphamosaic VideoCore processor
    const EM_TMM_GPP  = 96  #Thompson Multimedia General Purpose Processor
    const EM_NS32K    = 97  #National Semiconductor 32000 series
    const EM_TPC  = 98  #Tenor Network TPC processor
    const EM_SNP1K    = 99  #Trebia SNP 1000 processor
    const EM_ST200    = 100 #STMicroelectronics (www.st.com) ST200 microcontroller
    const EM_IP2K = 101 #Ubicom IP2xxx microcontroller family
    const EM_MAX  = 102 #MAX Processor
    const EM_CR   = 103 #National Semiconductor CompactRISC microprocessor
    const EM_F2MC16   = 104 #Fujitsu F2MC16
    const EM_MSP430   = 105 #Texas Instruments embedded microcontroller msp430
    const EM_BLACKFIN = 106 #Analog Devices Blackfin (DSP) processor
    const EM_SE_C33   = 107 #S1C33 Family of Seiko Epson processors
    const EM_SEP  = 108 #Sharp embedded microprocessor
    const EM_ARCA = 109 #Arca RISC Microprocessor
    const EM_UNICORE  = 110 #Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
    const EM_EXCESS   = 111 #eXcess: 16/32/64-bit configurable embedded CPU
    const EM_DXP  = 112 #Icera Semiconductor Inc. Deep Execution Processor
    const EM_ALTERA_NIOS2 = 113 #Altera Nios II soft-core processor
    const EM_CRX  = 114 #National Semiconductor CompactRISC CRX microprocessor
    const EM_XGATE    = 115 #Motorola XGATE embedded processor
    const EM_C166 = 116 #Infineon C16x/XC16x processor
    const EM_M16C = 117 #Renesas M16C series microprocessors
    const EM_DSPIC30F = 118 #Microchip Technology dsPIC30F Digital Signal Controller
    const EM_CE   = 119 #Freescale Communication Engine RISC core
    const EM_M32C = 120 #Renesas M32C series microprocessors
    #121-130 Reserved for future use
    const EM_TSK3000  = 131 #Altium TSK3000 core
    const EM_RS08 = 132 #Freescale RS08 embedded processor
    const EM_SHARC    = 133 #Analog Devices SHARC family of 32-bit DSP processors
    const EM_ECOG2    = 134 #Cyan Technology eCOG2 microprocessor
    const EM_SCORE7   = 135 #Sunplus S+core7 RISC processor
    const EM_DSP24    = 136 #New Japan Radio (NJR) 24-bit DSP Processor
    const EM_VIDEOCORE3   = 137 #Broadcom VideoCore III processor
    const EM_LATTICEMICO32    = 138 #RISC processor for Lattice FPGA architecture
    const EM_SE_C17   = 139 #Seiko Epson C17 family
    const EM_TI_C6000 = 140 #The Texas Instruments TMS320C6000 DSP family
    const EM_TI_C2000 = 141 #The Texas Instruments TMS320C2000 DSP family
    const EM_TI_C5500 = 142 #The Texas Instruments TMS320C55x DSP family
    #143-159 Reserved for future use
    const EM_MMDSP_PLUS   = 160 #STMicroelectronics 64bit VLIW Data Signal Processor
    const EM_CYPRESS_M8C  = 161 #Cypress M8C microprocessor
    const EM_R32C = 162 #Renesas R32C series microprocessors
    const EM_TRIMEDIA = 163 #NXP Semiconductors TriMedia architecture family
    const EM_QDSP6    = 164 #QUALCOMM DSP6 Processor
    const EM_8051 = 165 #Intel 8051 and variants
    const EM_STXP7X   = 166 #STMicroelectronics STxP7x family of configurable and extensible RISC processors
    const EM_NDS32    = 167 #Andes Technology compact code size embedded RISC processor family
    const EM_ECOG1    = 168 #Cyan Technology eCOG1X family
    const EM_ECOG1X   = 168 #Cyan Technology eCOG1X family
    const EM_MAXQ30   = 169 #Dallas Semiconductor MAXQ30 Core Micro-controllers
    const EM_XIMO16   = 170 #New Japan Radio (NJR) 16-bit DSP Processor
    const EM_MANIK    = 171 #M2000 Reconfigurable RISC Microprocessor
    const EM_CRAYNV2  = 172 #Cray Inc. NV2 vector architecture
    const EM_RX   = 173 #Renesas RX family
    const EM_METAG    = 174 #Imagination Technologies META processor architecture
    const EM_MCST_ELBRUS  = 175 #MCST Elbrus general purpose hardware architecture
    const EM_ECOG16   = 176 #Cyan Technology eCOG16 family
    const EM_CR16 = 177 #National Semiconductor CompactRISC CR16 16-bit microprocessor
    const EM_ETPU = 178 #Freescale Extended Time Processing Unit
    const EM_SLE9X    = 179 #Infineon Technologies SLE9X core
    const EM_L10M = 180 #Intel L10M
    const EM_K10M = 181 #Intel K10M
    #182 Reserved for future Intel use
    const EM_AARCH64  = 183 #ARM 64-bit architecture (AARCH64)
    #184 Reserved for future ARM use
    const EM_AVR32    = 185 #Atmel Corporation 32-bit microprocessor family
    const EM_STM8 = 186 #STMicroeletronics STM8 8-bit microcontroller
    const EM_TILE64   = 187 #Tilera TILE64 multicore architecture family
    const EM_TILEPRO  = 188 #Tilera TILEPro multicore architecture family
    const EM_MICROBLAZE   = 189 #Xilinx MicroBlaze 32-bit RISC soft processor core
    const EM_CUDA = 190 #NVIDIA CUDA architecture
    const EM_TILEGX   = 191 #Tilera TILE-Gx multicore architecture family
    const EM_CLOUDSHIELD  = 192 #CloudShield architecture family
    const EM_COREA_1ST    = 193 #KIPO-KAIST Core-A 1st generation processor family
    const EM_COREA_2ND    = 194 #KIPO-KAIST Core-A 2nd generation processor family
    const EM_ARC_COMPACT2 = 195 #Synopsys ARCompact V2
    const EM_OPEN8    = 196 #Open8 8-bit RISC soft processor core
    const EM_RL78 = 197 #Renesas RL78 family
    const EM_VIDEOCORE5   = 198 #Broadcom VideoCore V processor
    const EM_78KOR    = 199 #Renesas 78KOR family
    const EM_56800EX  = 200 #Freescale 56800EX Digital Signal Controller (DSC)
    const EM_BA1  = 201 #Beyond BA1 CPU architecture
    const EM_BA2  = 202 #Beyond BA2 CPU architecture
    const EM_XCORE    = 203 #XMOS xCORE processor family
    const EM_MCHP_PIC = 204 #Microchip 8-bit PIC(r) family
    #205-209 Reserved
    const EM_KM32        = 210 #KM211 KM32
    const EM_KMX32       = 211 #KM211 KMX32
    const EM_EMX16       = 212 #KM211 KMX16
    const EM_EMX8        = 213 #KM211 KMX8
    const EM_KVARC       = 214 #KM211 KVARC
    const EM_CDP         = 215 #Paneve CDP
    const EM_COGE        = 216 #Cognitive Smart Memory Processor
    const EM_COOL        = 217 #Bluechip CoolEngine
    const EM_NORC        = 218 #Nanoradio Optimized RISC
    const EM_CSR_KALIMBA = 219 #CSR Kalimba
    const EM_Z80         = 220 #Zilog Z80
    const EM_VISIUM      = 221 #Controls and Data Services VISIUMcore
    const EM_FT32        = 222 #FTDI Chip FT32
    const EM_MOXIE       = 223 #Moxie processor
    const EM_AMDGPU      = 224 #AMD GPU
    #225-242 Reserved
    const EM_RISCV       = 243 #RISC-V
    const EM_BPF         = 247 #Linux BPF -- in-kernel virtual machine
end

# Special Section Indices
const SHN_UNDEF   = 0
const SHN_LORESERVE   = 0xff00
const SHN_LOPROC  = 0xff00
const SHN_HIPROC  = 0xff1f
const SHN_LOOS    = 0xff20
const SHN_HIOS    = 0xff3f
const SHN_ABS     = 0xfff1
const SHN_COMMON  = 0xfff2
const SHN_XINDEX  = 0xffff
const SHN_HIRESERVE   = 0xffff
 
# sh_type constants
@constants SHT_TYPES "SHT_" begin
    const SHT_NULL          =  0
    const SHT_PROGBITS      =  1
    const SHT_SYMTAB        =  2
    const SHT_STRTAB        =  3
    const SHT_RELA          =  4
    const SHT_HASH          =  5
    const SHT_DYNAMIC       =  6
    const SHT_NOTE          =  7
    const SHT_NOBITS        =  8
    const SHT_REL           =  9
    const SHT_SHLIB         = 10
    const SHT_DYNSYM        = 11
    const SHT_INIT_ARRAY    = 14
    const SHT_FINI_ARRAY    = 15
    const SHT_PREINIT_ARRAY = 16
    const SHT_GROUP         = 17
    const SHT_SYMTAB_SHNDX  = 18
end
@constants SHT_MASKS "SHT_" begin
    const SHT_LOOS          = 0x60000000
    const SHT_HIOS          = 0x6fffffff
    const SHT_LOPROC        = 0x70000000
    const SHT_HIPROC        = 0x7fffffff
    const SHT_LOUSER        = 0x80000000
    const SHT_HIUSER        = 0xffffffff
end

# Section Attribute Flags
@constants SHF_FLAGS "SHF_" begin
    const SHF_WRITE                 =   0x1
    const SHF_ALLOC                 =   0x2
    const SHF_EXECINSTR             =   0x4
    const SHF_MERGE                 =  0x10
    const SHF_STRINGS               =  0x20
    const SHF_INFO_LINK             =  0x40
    const SHF_LINK_ORDER            =  0x80
    const SHF_OS_NONCONFORMING      = 0x100
    const SHF_GROUP                 = 0x200
    const SHF_TLS                   = 0x400
end
@constants SHF_MASKS "SHF_" begin
    const SHF_MASKOS                = 0x0f000000
    const SHF_MASKPROC              = 0xf0000000
end

# Section Group Flags
const GRP_COMDAT  = 0x1
const GRP_MASKOS  = 0x0ff00000
const GRP_MASKPROC    = 0xf0000000
 
# Symbol Binding
const STB_LOCAL   = 0
const STB_GLOBAL  = 1
const STB_WEAK    = 2
const STB_LOOS    = 10
const STB_HIOS    = 12
const STB_LOPROC  = 13
const STB_HIPROC  = 15
 
# Symbol Types
const STT_NOTYPE  = 0
const STT_OBJECT  = 1
const STT_FUNC    = 2
const STT_SECTION = 3
const STT_FILE    = 4
const STT_COMMON  = 5
const STT_TLS = 6
const STT_LOOS    = 10
const STT_HIOS    = 12
const STT_LOPROC  = 13
const STT_HIPROC  = 15
 
# Symbol Visibility
const STV_DEFAULT = 0
const STV_INTERNAL    = 1
const STV_HIDDEN  = 2
const STV_PROTECTED   = 3
 
# ptype constants
@constants P_TYPE "PT_" begin
    const PT_NULL           = 0
    const PT_LOAD           = 1
    const PT_DYNAMIC        = 2
    const PT_INTERP         = 3
    const PT_NOTE           = 4
    const PT_SHLIB          = 5
    const PT_PHDR           = 6
    const PT_TLS            = 7
    const PT_LOOS           = 0x60000000
    const PT_GNU_EH_FRAME   = 0x6474e550
    const PT_GNU_STACK      = 0x6474e551
    const PT_GNU_RELRO      = 0x6474e552
    const PT_PAX_FLAGS      = 0x65041580
    const PT_HIOS           = 0x6fffffff
    const PT_LOPROC         = 0x70000000
    const PT_HIPROC         = 0x7fffffff
end
 
# p_flags constants
const PF_X    = 0x1 #Execute
const PF_W    = 0x2 #Write
const PF_R    = 0x4 #Read
const PF_MASKOS   = 0x0ff00000  #Unspecified
const PF_MASKPROC = 0xf0000000  #Unspecified
 
# X86_64 relocations
@constants R_X86_64 "" begin
    const R_X86_64_NONE              =   0
    const R_X86_64_64                =   1
    const R_X86_64_PC32              =   2
    const R_X86_64_GOT32             =   3
    const R_X86_64_PLT32             =   4
    const R_X86_64_COPY              =   5
    const R_X86_64_GLOB_DAT          =   6
    const R_X86_64_JUMP_SLOT         =   7
    const R_X86_64_RELATIVE          =   8
    const R_X86_64_GOTPCREL          =   9
    const R_X86_64_32                =  10
    const R_X86_64_32S               =  11
    const R_X86_64_16                =  12
    const R_X86_64_PC16              =  13
    const R_X86_64_8                 =  14
    const R_X86_64_PC8               =  15
    const R_X86_64_DTPMOD64          =  16
    const R_X86_64_DTPOFF64          =  17
    const R_X86_64_TPOFF64           =  18
    const R_X86_64_TLSGD             =  19
    const R_X86_64_TLSLD             =  20
    const R_X86_64_DTPOFF32          =  21
    const R_X86_64_GOTTPOFF          =  22
    const R_X86_64_TPOFF32           =  23
    const R_X86_64_PC64              =  24
    const R_X86_64_GOTOFF64          =  25
    const R_X86_64_GOTPC32           =  26
    const R_X86_64_GOT64             =  27
    const R_X86_64_GOTPCREL64        =  28
    const R_X86_64_GOTPC64           =  29
    const R_X86_64_GOTPLT64          =  30
    const R_X86_64_PLTOFF64          =  31
    const R_X86_64_SIZE32            =  32
    const R_X86_64_SIZE64            =  33
    const R_X86_64_GOTPC32_TLSDESC   =  34
    const R_X86_64_TLSDESC_CALL      =  35
    const R_X86_64_TLSDESC           =  36
    const R_X86_64_IRELATIVE         =  37
end

@constants AUXV_TYPE "AT_" begin
    const AT_NULL         = 0
    const AT_IGNORE       = 1
    const AT_EXECFD       = 2
    const AT_PHDR         = 3
    const AT_PHENT        = 4
    const AT_PHNUM        = 5
    const AT_PAGESZ       = 6
    const AT_BASE         = 7
    const AT_FLAGS        = 8
    const AT_ENTRY        = 9
    const AT_NOTELF       = 10
    const AT_UID          = 11
    const AT_EUID         = 12
    const AT_GID          = 13
    const AT_EGID         = 14
    const AT_PLATFORM     = 15
    const AT_HWCAP        = 16
    const AT_CLKTCK       = 17
    const AT_SYSINFO      = 32
    const AT_SYSINFO_EHDR = 33
end

@constants DYNAMIC_TYPE "DT_" begin
    const DT_NULL         = 0
    const DT_NEEDED       = 1
    const DT_PLTRELSZ     = 2
    const DT_PLTGOT       = 3
    const DT_HASH         = 4
    const DT_STRTAB       = 5
    const DT_SYMTAB       = 6
    const DT_RELA         = 7
    const DT_RELASZ       = 8
    const DT_RELAENT      = 9
    const DT_STRSZ        = 10
    const DT_SYMENT       = 11
    const DT_INIT         = 12
    const DT_FINI         = 13
    const DT_SONAME       = 14
    const DT_RPATH        = 15
    const DT_SYMBOLIC     = 16
    const DT_REL          = 17
    const DT_RELSZ        = 18
    const DT_RELENT       = 19
    const DT_PLTREL       = 20
    const DT_DEBUG        = 21
    const DT_TEXTREL      = 22
    const DT_JMPREL       = 23
    const DT_BIND_NOW     = 24
    const DT_INIT_ARRAY	  = 25
    const DT_FINI_ARRAY	  = 26
    const DT_INIT_ARRAYSZ =	27
    const DT_FINI_ARRAYSZ =	28
    const DT_RUNPATH	  = 29
    const DT_FLAGS	      = 30
    const DT_ENCODING     = 32
    const OLD_DT_LOOS     = 0x60000000
    const DT_LOOS         = 0x6000000d
    const DT_HIOS         = 0x6ffff000
    const DT_VALRNGLO     = 0x6ffffd00
    const DT_VALRNGHI     = 0x6ffffdff
    const DT_ADDRRNGLO    = 0x6ffffe00
    const DT_CONFIG       = 0x6ffffefa
    const DT_DEPAUDIT     = 0x6ffffefb
    const DT_AUDIT        = 0x6ffffefc
    const DT_ADDRRNGHI    = 0x6ffffeff
    const DT_VERSYM       = 0x6ffffff0
    const DT_RELACOUNT    = 0x6ffffff9
    const DT_RELCOUNT     = 0x6ffffffa
    const DT_FLAGS_1      = 0x6ffffffb
    const DT_VERDEF       = 0x6ffffffc
    const DT_VERDEFNUM    = 0x6ffffffd
    const DT_VERNEED      = 0x6ffffffe
    const DT_VERNEEDNUM   = 0x6fffffff
    const OLD_DT_HIOS     = 0x6fffffff
    const DT_LOPROC       = 0x70000000
    const DT_AUXILIARY   = 0x7ffffffd
    const DT_FILTER       = 0x7fffffff
end
