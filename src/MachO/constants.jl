# Magic numbers
@constants MAGICS "" begin
    const MH_MAGIC = 0xfeedface
    const MH_CIGAM = bswap(MH_MAGIC)

    const MH_MAGIC_64 = 0xfeedfacf
    const MH_CIGAM_64 = bswap(MH_MAGIC_64)

    const FAT_MAGIC = 0xCAFEBABE
    const FAT_CIGAM = bswap(FAT_MAGIC)

    const FAT_MAGIC_64 = 0xCAFEBABF
    const FAT_CIGAM_64 = bswap(FAT_MAGIC_64)

    const FAT_MAGIC_METAL = 0xCBFEBABE
    const FAT_CIGAM_METAL = bswap(FAT_MAGIC_METAL)

    const METALLIB_MAGIC = 0x424c544d   # "MTLB" in ascii
end

const CPU_ARCH_MASK     = 0xff000000
const CPU_ARCH_ABI64    = 0x01000000
const CPU_ARCH_ABI64_32 = 0x02000000

@constants CPUTYPES "CPU_TYPE_" begin
    const CPU_TYPE_ANY          = reinterpret(UInt32,Int32(-1))
    const CPU_TYPE_VAX          = 1
    # skip
    # skip
    # skip
    # skip
    const CPU_TYPE_MC680x0      = 6
    const CPU_TYPE_X86          = 7
    const CPU_TYPE_X86_64       = CPU_TYPE_X86 | CPU_ARCH_ABI64
    const CPU_TYPE_MIPS         = 8
    # skip
    const CPU_TYPE_MC98000      = 10
    const CPU_TYPE_HPPA         = 11
    const CPU_TYPE_ARM          = 12
    const CPU_TYPE_MC88000      = 13
    const CPU_TYPE_SPARC        = 14
    const CPU_TYPE_I860         = 15
    const CPU_TYPE_ALPHA        = 16
    # skip
    const CPU_TYPE_POWERPC      = 18
    const CPU_TYPE_POWERPC64    = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
    const CPU_TYPE_ARM64        = CPU_TYPE_ARM | CPU_ARCH_ABI64
    const CPU_TYPE_ARM64_32     = CPU_TYPE_ARM | CPU_ARCH_ABI64_32
end

function macho_cpu_to_arch(cputype::UInt32)
    if cputype ∈ (CPU_TYPE_X86,)
        return "i686"
    elseif cputype ∈ (CPU_TYPE_X86_64,)
        return "x86_64"
    elseif cputype ∈ (CPU_TYPE_ARM,)
        return "armv7l"
    elseif cputype ∈ (CPU_TYPE_POWERPC64,)
        return "ppc64le"
    elseif cputype ∈ (CPU_TYPE_ARM64,)
        return "aarch64"
    end
end


# TODO subtype constants
@constants NLISTTYPES "N_" begin
    const N_STAB         = 0xe0
    const N_PEXT         = 0x10
    const N_TYPE         = 0x0e
    const N_EXT          = 0x01
    const N_UNDF         = 0x00
    const N_ABS          = 0x02
    const N_SECT         = 0x0e
    const N_PBUD         = 0x0c
    const N_INDR         = 0x0a
end

@constants NDESC "N_" begin
    const N_WEAK_REF      = 0x0040
    const N_WEAK_DEF      = 0x0080
    const N_ARM_THUMB_DEF = 0x0008
end

const N_REF_TO_WEAK = N_WEAK_DEF

const NO_SECT  = 0x0
const MAX_SECT = 0xff

@constants FILETYPES "MH_" begin
    const MH_OBJECT      = 0x1     # relocatable object file
    const MH_EXECUTE     = 0x2     # demand paged executable file
    const MH_FVMLIB      = 0x3     # fixed VM shared library file
    const MH_CORE        = 0x4     # core file
    const MH_PRELOAD     = 0x5     # preloaded executable file
    const MH_DYLIB       = 0x6     # dynamically bound shared library
    const MH_DYLINKER    = 0x7     # dynamic link editor
    const MH_BUNDLE      = 0x8     # dynamically bound bundle file
    const MH_DYLIB_STUB  = 0x9     # shared library stub for static linking only
    const MH_DSYM        = 0xa     # companion file with only debug sections
    const MH_KEXT_BUNDLE = 0xb     # x86_64 kexts
end

# Constants for the flags field of the mach_header

@constants FLAGS "MH_" begin
    # the object file has no undefined references
    const MH_NOUNDEFS                   = 0x1
    # the object file is the output of an incremental link
    # against a base file and can't be link edited again
    const MH_INCRLINK                   = 0x2
    # the object file is input for the dynamic linker
    # and can't be staticly link edited again
    const MH_DYLDLINK                   = 0x4
    # the object file's undefined references are bound
    # by the dynamic linker when loaded
    const MH_BINDATLOAD                 = 0x8
    # the file has its dynamic undefined references prebound
    const MH_PREBOUND                   = 0x10
    # the file has its read-only and read-write segments split
    const MH_SPLIT_SEGS                 = 0x20
    # the shared library init routine is to be run
    # lazily via catching memory faults to its writeable segments
    # (obsolete)
    const MH_LAZY_INIT                  = 0x40
    # the image is using two-level name space bindings
    const MH_TWOLEVEL                   = 0x80
    # the executable is forcing all image to use flat
    # name space bindings
    const MH_FORCE_FLAT                 = 0x100
    # this umbrella guarantees no multiple defintions of
    # symbols in its sub-images so the two-level namespace
    # hints can always be used
    const MH_NOMULTIDEFS                = 0x100
    # do not have dyld notify the prebinding agent about this
    # executable
    const MH_NOFIXPREBINDING            = 0x200
    # the binary is not prebound but can have its prebinding
    # redone. only used when MH_PREBOUND is not set.
    const MH_PREBINDABLE                = 0x400
    # indicates that this binary binds to all two-level
    # namespace modules of its dependent libraries.
    # only used when MH_PREBINDABLE and MH_TWOLEVEL are both set
    const MH_ALLMODSBOUND               = 0x800
    # safe to divide up the sections into sub-sections
    # via symbols for dead code stripping
    const MH_SUBSECTIONS_VIA_SYMBOLS    = 0x1000
    const MH_CANONICAL                  = 0x2000
    const MH_WEAK_DEFINES               = 0x4000
    const MH_BINDS_TO_WEAK              = 0x8000
    const MH_ALLOW_STACK_EXECUTION      = 0x10000
    const MH_ROOT_SAFE                  = 0x20000
    const MH_SETUID_SAFE                = 0x40000
    const MH_NO_REEXPORTED_DYLIBS       = 0x80000
    const MH_PIE                        = 0x100000
    const MH_DEAD_STRIPPABLE_DYLIB      = 0x200000
    const MH_HAS_TLV_DESCRIPTORS        = 0x400000
    const MH_NO_HEAP_EXECUTION          = 0x800000
end


# Load command types.  Note that we have dropped the LC_REQ_DYLD flag OR'ed
# into many of these types to aid in easy usage of these constants.  Since
# the meaning of LC_REQ_DYLD is to denote to the linker which load commands
# cannot be safely ignored when loading, this does not affect us much, and
# we disregard it entirely.

const LC_REQ_DYLD = 0x80000000
@constants LCTYPES "LC_" begin
    const LC_SEGMENT            = 0x1   # segment of this file to be mapped
    const LC_SYMTAB             = 0x2   # link-edit stab symbol table info
    const LC_SYMSEG             = 0x3   # link-edit gdb symbol table info (obsolete)
    const LC_THREAD             = 0x4   # thread
    const LC_UNIXTHREAD         = 0x5   # unix thread (includes a stack)
    const LC_LOADFVMLIB         = 0x6   # load a specified fixed VM shared library
    const LC_IDFVMLIB           = 0x7   # fixed VM shared library identification
    const LC_IDENT              = 0x8   # object identification info (obsolete)
    const LC_FVMFILE            = 0x9   # fixed VM file inclusion (internal use)
    const LC_PREPAGE            = 0xa   # prepage command (internal use)
    const LC_DYSYMTAB           = 0xb   # dynamic link-edit symbol table info
    const LC_LOAD_DYLIB         = 0xc   # load a dynamically linked shared library
    const LC_ID_DYLIB           = 0xd   # dynamically linked shared lib ident
    const LC_LOAD_DYLINKER      = 0xe   # load a dynamic linker
    const LC_ID_DYLINKER        = 0xf   # dynamic linker identification
    const LC_PREBOUND_DYLIB     = 0x10  # modules prebound for a dynamically linked shared library
    const LC_ROUTINES           = 0x11  # image routines
    const LC_SUB_FRAMEWORK      = 0x12  # sub framework
    const LC_SUB_UMBRELLA       = 0x13  # sub umbrella
    const LC_SUB_CLIENT         = 0x14  # sub client
    const LC_SUB_LIBRARY        = 0x15  # sub library
    const LC_TWOLEVEL_HINTS     = 0x16  # two-level namespace lookup hints
    const LC_PREBIND_CKSUM      = 0x17  # prebind checksum
    #
    # load a dynamically linked shared library that is allowed to be missing
    # (all symbols are weak imported).
    #
    const LC_LOAD_WEAK_DYLIB        = 0x18
    const LC_SEGMENT_64             = 0x19 # 64-bit segment of this file to be mapped
    const LC_ROUTINES_64            = 0x1a # 64-bit image routines
    const LC_UUID                   = 0x1b # the uuid
    const LC_RPATH                  = 0x1c # runpath additions
    const LC_CODE_SIGNATURE         = 0x1d # local of code signature
    const LC_SEGMENT_SPLIT_INFO     = 0x1e # local of info to split segments
    const LC_REEXPORT_DYLIB         = 0x1f # load and re-export dylib
    const LC_LAZY_LOAD_DYLIB        = 0x20 # delay load of dylib until first use
    const LC_ENCRYPTION_INFO        = 0x21 # encrypted segment information
    const LC_DYLD_INFO              = 0x22 # compressed dyld information
    const LC_DYLD_INFO_ONLY         = 0x22 # compressed dyld information only
    const LC_LOAD_UPWARD_DYLIB      = 0x23 # load upward dylib
    const LC_VERSION_MIN_MACOSX     = 0x24 # build for MacOSX min OS version
    const LC_VERSION_MIN_IPHONEOS   = 0x25 # build for iPhoneOS min OS version
    const LC_FUNCTION_STARTS        = 0x26 # compressed table of function start addresses
    const LC_DYLD_ENVIRONMENT       = 0x27 # string for dyld to treat like environment variable
    const LC_MAIN                   = 0x28 # replacement for LC_UNIXTHREAD
    const LC_DATA_IN_CODE           = 0x29 # table of non-instructions in __text
    const LC_SOURCE_VERSION         = 0x2A # source version used to build binary
    const LC_DYLIB_CODE_SIGN_DRS    = 0x2B # Code signing DRs copied from linked dylibs
    const LC_ENCRYPTION_INFO_64     = 0x2C # 64-bit encrypted segment information
    const LC_LINKER_OPTION          = 0x2D # linker options in MH_OBJECT files
    const LC_LINKER_OPTIMIZATION_HINT = 0x2E # optimization hints in MH_OBJECT files
    const LC_VERSION_MIN_TVOS       = 0x2F # build for AppleTV min OS version
    const LC_VERSION_MIN_WATCHOS    = 0x30 # build for Watch min OS version
    const LC_NOTE                   = 0x31 # arbitrary data included within a Mach-O file
    const LC_BUILD_VERSION          = 0x32 # build for platform min OS version
end

# Platform identifiers stored in `LC_BUILD_VERSION` load commands
@constants PLATFORMS "PLATFORM_" begin
    const PLATFORM_MACOS                = 1
    const PLATFORM_IOS                  = 2
    const PLATFORM_TVOS                 = 3
    const PLATFORM_WATCHOS              = 4
    const PLATFORM_BRIDGEOS             = 5
    const PLATFORM_MACCATALYST          = 6
    const PLATFORM_IOSSIMULATOR         = 7
    const PLATFORM_TVOSSIMULATOR        = 8
    const PLATFORM_WATCHOSSIMULATOR     = 9
    const PLATFORM_DRIVERKIT            = 10
    const PLATFORM_VISIONOS             = 11
    const PLATFORM_VISIONOSSIMULATOR    = 12
end


const SECTION_TYPE          = 0x000000ff # 256 section types
const SECTION_ATTRIBUTES    = 0xffffff00 # 24 section attributes

@constants SECTYPES "" begin
    # regular section
    const S_REGULAR                                 = 0x0
    # zero fill on demand section
    const S_ZEROFILL                                = 0x1
    # section with only literal C string
    const S_CSTRING_LITERALS                        = 0x2
    # section with only 4 byte literals
    const S_4BYTE_LITERALS                          = 0x3
    # section with only 8 byte literals
    const S_8BYTE_LITERALS                          = 0x4
    # section with only pointers to literals
    const S_LITERAL_POINTERS                        = 0x5
#
#  For the two types of symbol pointers sections and the symbol stubs section
#  they have indirect symbol table entries.  For each of the entries in the
#  section the indirect symbol table entries, in corresponding order in the
#  indirect symbol table, start at the index stored in the reserved1 field
#  of the section structure.  Since the indirect symbol table entries
#  correspond to the entries in the section the number of indirect symbol table
#  entries is inferred from the size of the section divided by the size of the
#  entries in the section.  For symbol pointers sections the size of the entries
#  in the section is 4 bytes and for symbol stubs sections the byte size of the
#  stubs is stored in the reserved2 field of the section structure.

    # section with only non-lazy symbol pointers
    const S_NON_LAZY_SYMBOL_POINTERS                = 0x6
    # section with only lazy symbol
    const S_LAZY_SYMBOL_POINTERS                    = 0x7
    # section with only symbol stubs, byte
    # size of stub in the reserved2 field
    const S_SYMBOL_STUBS                            = 0x8
    # section with only function pointers
    # for initialization
    const S_MOD_INIT_FUNC_POINTERS                  = 0x9
    # section with only function pointers
    # for initialization
    const S_MOD_TERM_FUNC_POINTERS                  = 0xa
    # section contains symbols that
    # are to be coalesced
    const S_COALESCED                               = 0xb
    # zero fill on demand section
    # (that can be larger than 4 gigabytes)
    const S_GB_ZEROFILL                             = 0xc
    # section with only pairs of function
    # pointers for interposing
    const S_INTERPOSING                             = 0xd
    # section with only 16 byte literals
    const S_16BYTE_LITERALS                         = 0xe
    # section contains DTrace Object Format
    const S_DTRACE_DOF                              = 0xf
    # section with only lazy symbol pointers
    # to lazy loaded dylibs
    const S_LAZY_DYLIB_SYMBOL_POINTERS              = 0x10
    # template of initial values for TLVs
    const S_THREAD_LOCAL_REGULAR                    = 0x11
    # template of initial values for TLVs
    const S_THREAD_LOCAL_ZEROFILL                   = 0x12
    # TLV descriptors
    const S_THREAD_LOCAL_VARIABLES                  = 0x13
    # pointers to TLV descriptors
    const S_THREAD_LOCAL_VARIABLE_POINTERS          = 0x14
    # functions to call to initialize TLV values
    const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS     = 0x15
end

const SECTION_ATTRIBUTES_USR = 0xff000000
const SECTION_ATTRIBUTES_SYS = 0x00ffff00

@constants SECATTRS "S_ATTR_" begin
    # section contains only true machine instructions
    const S_ATTR_PURE_INSTRUCTIONS      = 0x80000000
    # section contains coalesced symbols that are not to be
    # in a ranlib table of contents
    const S_ATTR_NO_TOC                 = 0x40000000
    # ok to strip static symbols in this section in files
    # with the MH_DYLDLINK flag
    const S_ATTR_STRIP_STATIC_SYMS      = 0x20000000
    # no dead stripping
    const S_ATTR_NO_DEAD_STRIP          = 0x10000000
    # blocks are live if they reference live blocks
    const S_ATTR_LIVE_SUPPORT           = 0x08000000
    # Used with i386 code stubs written on by dyld
    const S_ATTR_SELF_MODIFYING_CODE    = 0x04000000
    # a debug section
    const S_ATTR_DEBUG                  = 0x02000000
    # section contains some machine instructions
    const S_ATTR_SOME_INSTRUCTIONS      = 0x00000400
    # section has external relocation entries
    const S_ATTR_EXT_RELOC              = 0x00000200
    # section has local relocation entries
    const S_ATTR_LOC_RELOC              = 0x00000100
end

@constants UNWIND_FLAGS "UNWIND_" begin
    const UNWIND_IS_NOT_FUNCTION_START  = 0x80000000
    const UNWIND_HAS_LSDA               = 0x40000000
    const UNWIND_PERSONALITY_MASK       = 0x30000000
end

@constants UNWIND_X86 "UNWIND_X86_" begin
    const UNWIND_X86_MODE_MASK                          = 0x0F000000
    const UNWIND_X86_MODE_EBP_FRAME                     = 0x01000000
    const UNWIND_X86_MODE_STACK_IMMD                    = 0x02000000
    const UNWIND_X86_MODE_STACK_IND                     = 0x03000000
    const UNWIND_X86_MODE_DWARF                         = 0x04000000

    const UNWIND_X86_EBP_FRAME_REGISTERS                = 0x00007FFF
    const UNWIND_X86_EBP_FRAME_OFFSET                   = 0x00FF0000

    const UNWIND_X86_FRAMELESS_STACK_SIZE               = 0x00FF0000
    const UNWIND_X86_FRAMELESS_STACK_ADJUST             = 0x0000E000
    const UNWIND_X86_FRAMELESS_STACK_REG_COUNT          = 0x00001C00
    const UNWIND_X86_FRAMELESS_STACK_REG_PERMUTATION    = 0x000003FF

    const UNWIND_X86_DWARF_SECTION_OFFSET               = 0x00FFFFFF
end

@constants UNWIND_X86_REGS "UNWIND_X86_REG_" begin
    const UNWIND_X86_REG_NONE   = 0
    const UNWIND_X86_REG_EBX    = 1
    const UNWIND_X86_REG_ECX    = 2
    const UNWIND_X86_REG_EDX    = 3
    const UNWIND_X86_REG_EDI    = 4
    const UNWIND_X86_REG_ESI    = 5
    const UNWIND_X86_REG_EBP    = 6
end

@constants UNWIND_X86_64 "UNWIND_X86_64_" begin
    const UNWIND_X86_64_MODE_MASK                          = 0x0F000000
    const UNWIND_X86_64_MODE_EBP_FRAME                     = 0x01000000
    const UNWIND_X86_64_MODE_STACK_IMMD                    = 0x02000000
    const UNWIND_X86_64_MODE_STACK_IND                     = 0x03000000
    const UNWIND_X86_64_MODE_DWARF                         = 0x04000000

    const UNWIND_X86_64_EBP_FRAME_REGISTERS                = 0x00007FFF
    const UNWIND_X86_64_EBP_FRAME_OFFSET                   = 0x00FF0000

    const UNWIND_X86_64_FRAMELESS_STACK_SIZE               = 0x00FF0000
    const UNWIND_X86_64_FRAMELESS_STACK_ADJUST             = 0x0000E000
    const UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT          = 0x00001C00
    const UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION    = 0x000003FF

    const UNWIND_X86_64_DWARF_SECTION_OFFSET               = 0x00FFFFFF
end

@constants UNWIND_X86_64_REGS "UNWIND_X86_64_REG_" begin
    const UNWIND_X86_64_REG_NONE    = 0
    const UNWIND_X86_64_REG_RBX     = 1
    const UNWIND_X86_64_REG_R12     = 2
    const UNWIND_X86_64_REG_R13     = 3
    const UNWIND_X86_64_REG_R14     = 4
    const UNWIND_X86_64_REG_R15     = 5
    const UNWIND_X86_64_REG_RBP     = 6
end

@constants UNWIND_SECOND_LEVEL "UNWIND_SECOND_LEVEL_" begin
    const UNWIND_SECOND_LEVEL_REGULAR       = 2
    const UNWIND_SECOND_LEVEL_COMPRESSED    = 3
end

@constants X86_64_RELOC "X86_64_RELOC_" begin
    const X86_64_RELOC_UNSIGNED        = 0
    const X86_64_RELOC_SIGNED          = 1
    const X86_64_RELOC_BRANCH          = 2
    const X86_64_RELOC_GOT_LOAD        = 3
    const X86_64_RELOC_GOT             = 4
    const X86_64_RELOC_SUBTRACTOR      = 5
    const X86_64_RELOC_SIGNED_1        = 6
    const X86_64_RELOC_SIGNED_2        = 7
    const X86_64_RELOC_SIGNED_4        = 8
    const X86_64_RELOC_TLV             = 9
end

@constants X86_THREAD_FLAVORS "" begin
    const x86_THREAD_STATE32    = 1
    const x86_FLOAT_STATE32     = 2
    const x86_EXCEPTION_STATE32 = 3
    const x86_THREAD_STATE64    = 4
    const x86_FLOAT_STATE64     = 5
    const x86_EXCEPTION_STATE64 = 6
    const x86_THREAD_STATE      = 7
    const x86_FLOAT_STATE       = 8
    const x86_EXCEPTION_STATE   = 9
    const x86_DEBUG_STATE32     = 10
    const x86_DEBUG_STATE64     = 11
    const x86_DEBUG_STATE       = 12
end

