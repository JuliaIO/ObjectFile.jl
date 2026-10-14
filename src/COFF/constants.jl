# # # Machine Types
@constants IMAGE_FILE_MACHINE "IMAGE_FILE_" begin
    const IMAGE_FILE_MACHINE_UNKNOWN        = 0x0       # The contents of this field are assumed to be applicable to any machine type
    const IMAGE_FILE_MACHINE_AM33           = 0x1d3     #   Matsushita AM33
    const IMAGE_FILE_MACHINE_AMD64          = 0x8664    #  x64
    const IMAGE_FILE_MACHINE_ARM            = 0x1c0     #   ARM little endian
    const IMAGE_FILE_MACHINE_ARMNT          = 0x1c4     #   ARMv7 (or higher) Thumb mode only
    const IMAGE_FILE_MACHINE_ARM64          = 0xaa64    #  ARMv8 in 64-bit mode
    const IMAGE_FILE_MACHINE_ARM64EC        = 0xa641    #  ARMv8 in 64-bit mode, with the x64 ABI
    const IMAGE_FILE_MACHINE_ARM64X         = 0xa64e    #  ARM64 and ARM64EC code together
    const IMAGE_FILE_MACHINE_EBC            = 0xebc     #   EFI byte code
    const IMAGE_FILE_MACHINE_I386           = 0x14c     #   Intel 386 or later processors and compatible processors
    const IMAGE_FILE_MACHINE_IA64           = 0x200     #   Intel Itanium processor family
    const IMAGE_FILE_MACHINE_M32R           = 0x9041    #  Mitsubishi M32R little endian
    const IMAGE_FILE_MACHINE_MIPS16         = 0x266     #   MIPS16
    const IMAGE_FILE_MACHINE_MIPSFPU        = 0x366     #   MIPS with FPU
    const IMAGE_FILE_MACHINE_MIPSFPU16      = 0x466     #   MIPS16 with FPU
    const IMAGE_FILE_MACHINE_POWERPC        = 0x1f0     #   Power PC little endian
    const IMAGE_FILE_MACHINE_POWERPCFP      = 0x1f1     #   Power PC with floating point support
    const IMAGE_FILE_MACHINE_R4000          = 0x166     #   MIPS little endian
    const IMAGE_FILE_MACHINE_SH3            = 0x1a2     #   Hitachi SH3
    const IMAGE_FILE_MACHINE_SH3DSP         = 0x1a3     #   Hitachi SH3 DSP
    const IMAGE_FILE_MACHINE_SH4            = 0x1a6     #   Hitachi SH4
    const IMAGE_FILE_MACHINE_SH5            = 0x1a8     #   Hitachi SH5
    const IMAGE_FILE_MACHINE_THUMB          = 0x1c2     #   ARM or Thumb (“interworking”)
    const IMAGE_FILE_MACHINE_WCEMIPSV2      = 0x169     #   MIPS little-endian WCE v2
end

function coff_machine_to_arch(machine::UInt16)
    if machine ∈ (IMAGE_FILE_MACHINE_I386,)
        return "i686"
    elseif machine ∈ (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_IA64)
        return "x86_64"
    elseif machine ∈ (IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_THUMB)
        return "armv7l"
    elseif machine ∈ (IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X)
        return "aarch64"
    elseif machine ∈ (IMAGE_FILE_MACHINE_POWERPC,)
        return "ppc64le"
    end
end

# # # Characteristics

@constants IMAGE_FILE_CHARACTERISTICS "IMAGE_FILE_" begin
    const IMAGE_FILE_RELOCS_STRIPPED            = 0x0001 # Image only, Windows CE, and Windows NT® and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    const IMAGE_FILE_EXECUTABLE_IMAGE           = 0x0002 # Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    const IMAGE_FILE_LINE_NUMS_STRIPPED         = 0x0004 # COFF line numbers have been removed. This flag is deprecated and should be zero.
    const IMAGE_FILE_LOCAL_SYMS_STRIPPED        = 0x0008 # COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    const IMAGE_FILE_AGGRESSIVE_WS_TRIM         = 0x0010 # Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    const IMAGE_FILE_LARGE_ADDRESS_AWARE        = 0x0020 # Application can handle > 2 GB addresses.
    const IMAGE_FILE_BYTES_REVERSED_LO          = 0x0080 # Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    #                                           = 0x0040 # This flag is reserved for future use.
    const IMAGE_FILE_32BIT_MACHINE              = 0x0100 # Machine is based on a 32-bit-word architecture.
    const IMAGE_FILE_DEBUG_STRIPPED             = 0x0200 # Debugging information is removed from the image file.
    const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP    = 0x0400 # If the image is on removable media, fully load it and copy it to the swap file.
    const IMAGE_FILE_NET_RUN_FROM_SWAP          = 0x0800 # If the image is on network media, fully load it and copy it to the swap file.
    const IMAGE_FILE_SYSTEM                     = 0x1000 # The image file is a system file, not a user program.
    const IMAGE_FILE_DLL                        = 0x2000 # The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    const IMAGE_FILE_UP_SYSTEM_ONLY             = 0x4000 # The file should be run only on a uniprocessor machine.
    const IMAGE_FILE_BYTES_REVERSED_HI          = 0x8000 # Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
end

# # # Magic Numbers
const MAGICPE32 = 0x10b
const MAGICPE   = 0x20b

# # # Windows Subsystem
const IMAGE_SUBSYSTEM_UNKNOWN                   =   0  # An unknown subsystem
const IMAGE_SUBSYSTEM_NATIVE                    =   1  # Device drivers and native Windows processes
const IMAGE_SUBSYSTEM_WINDOWS_GUI               =   2  # The Windows graphical user interface (GUI) subsystem
const IMAGE_SUBSYSTEM_WINDOWS_CUI               =   3  # The Windows character subsystem
const IMAGE_SUBSYSTEM_POSIX_CUI                 =   7  # The Posix character subsystem
const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI            =   9  # Windows CE
const IMAGE_SUBSYSTEM_EFI_APPLICATION           =   10 # An Extensible Firmware Interface (EFI) application
const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER   =   11 # An EFI driver with boot services
const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER        =   12 # An EFI driver with run-time services
const IMAGE_SUBSYSTEM_EFI_ROM                   =   13 # An EFI ROM image
const IMAGE_SUBSYSTEM_XBOX                      =   14 # XBOX


# # # DLL Characteristics

#                                                       = 0x0001 #  Reserved, must be zero
#                                                       = 0x0002 #  Reserved, must be zero
#                                                       = 0x0004 #  Reserved, must be zero
#                                                       = 0x0008 #  Reserved, must be zero
const IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE            = 0x0040 #  DLL can be relocated at load time.
const IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY         = 0x0080 #  Code Integrity checks are enforced.
const IMAGE_DLL_CHARACTERISTICS_NX_COMPAT               = 0x0100 #  Image is NX compatible.
const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION             = 0x0200 #  Isolation aware, but do not isolate the image.
const IMAGE_DLLCHARACTERISTICS_NO_SEH                   = 0x0400 #  Does not use structured exception (SE) handling. No SE handler may be called in this image.
const IMAGE_DLLCHARACTERISTICS_NO_BIND                  = 0x0800 #  Do not bind the image.
#                                                       = 0x1000 #  Reserved, must be zero
const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER               = 0x2000 #  A WDM driver.
const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE    = 0x8000 #  Terminal Server aware.

# # # Section Flags
@constants IMAGE_SCN_CHARACTERISTICS "IMAGE_SCN_" begin
    #                                         = 0x00000000 #  Reserved for future use.
    #                                         = 0x00000001 #  Reserved for future use.
    #                                         = 0x00000002 #  Reserved for future use.
    #                                         = 0x00000004 #  Reserved for future use.
    const IMAGE_SCN_TYPE_NO_PAD               = 0x00000008 #  The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    #                                         = 0x00000010 #  Reserved for future use.
    const IMAGE_SCN_CNT_CODE                  = 0x00000020 #  The section contains executable code.
    const IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040 #  The section contains initialized data.
    const IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080 #  The section contains uninitialized data.
    const IMAGE_SCN_LNK_OTHER                 = 0x00000100 #  Reserved for future use.
    const IMAGE_SCN_LNK_INFO                  = 0x00000200 #  The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    #                                         = 0x00000400 #  Reserved for future use.
    const IMAGE_SCN_LNK_REMOVE                = 0x00000800 #  The section will not become part of the image. This is valid only for object files.
    const IMAGE_SCN_LNK_COMDAT                = 0x00001000 #  The section contains COMDAT data. For more information, see section 5.5.6, “COMDAT Sections (Object Only).” This is valid only for object files.
    const IMAGE_SCN_GPREL                     = 0x00008000 #  The section contains data referenced through the global pointer (GP).
    const IMAGE_SCN_MEM_PURGEABLE             = 0x00020000 #  Reserved for future use.
    const IMAGE_SCN_MEM_16BIT                 = 0x00020000 #  For ARM machine types, the section contains Thumb code.  Reserved for future use with other machine types.
    const IMAGE_SCN_MEM_LOCKED                = 0x00040000 #  Reserved for future use.
    const IMAGE_SCN_MEM_PRELOAD               = 0x00080000 #  Reserved for future use.
    const IMAGE_SCN_ALIGN_1BYTES              = 0x00100000 #  Align data on a 1-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_2BYTES              = 0x00200000 #  Align data on a 2-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_4BYTES              = 0x00300000 #  Align data on a 4-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_8BYTES              = 0x00400000 #  Align data on an 8-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_16BYTES             = 0x00500000 #  Align data on a 16-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_32BYTES             = 0x00600000 #  Align data on a 32-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_64BYTES             = 0x00700000 #  Align data on a 64-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_128BYTES            = 0x00800000 #  Align data on a 128-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_256BYTES            = 0x00900000 #  Align data on a 256-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_512BYTES            = 0x00A00000 #  Align data on a 512-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_1024BYTES           = 0x00B00000 #  Align data on a 1024-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_2048BYTES           = 0x00C00000 #  Align data on a 2048-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_4096BYTES           = 0x00D00000 #  Align data on a 4096-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_8192BYTES           = 0x00E00000 #  Align data on an 8192-byte boundary. Valid only for object files.
    const IMAGE_SCN_LNK_NRELOC_OVFL           = 0x01000000 #  The section contains extended relocations.
    const IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000 #  The section can be discarded as needed.
    const IMAGE_SCN_MEM_NOT_CACHED            = 0x04000000 #  The section cannot be cached.
    const IMAGE_SCN_MEM_NOT_PAGED             = 0x08000000 #  The section is not pageable.
    const IMAGE_SCN_MEM_SHARED                = 0x10000000 #  The section can be shared in memory.
    const IMAGE_SCN_MEM_EXECUTE               = 0x20000000 #  The section can be executed as code.
    const IMAGE_SCN_MEM_READ                  = 0x40000000 #  The section can be read.
    const IMAGE_SCN_MEM_WRITE                 = 0x80000000 #  The section can be written to.
end
    const IMAGE_SCN_ALIGN_MASK                = 0x00F00000

# # # AMD64 Relocations
@constants IMAGE_REL_AMD64 "IMAGE_REL_AMD64_" begin
    const IMAGE_REL_AMD64_ABSOLUTE    = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_AMD64_ADDR64      = 0x0001 #  The 64-bit VA of the relocation target.
    const IMAGE_REL_AMD64_ADDR32      = 0x0002 #  The 32-bit VA of the relocation target.
    const IMAGE_REL_AMD64_ADDR32NB    = 0x0003 #  The 32-bit address without an image base (RVA).
    const IMAGE_REL_AMD64_REL32       = 0x0004 #  The 32-bit relative address from the byte following the relocation.
    const IMAGE_REL_AMD64_REL32_1     = 0x0005 #  The 32-bit address relative to byte distance 1 from the relocation.
    const IMAGE_REL_AMD64_REL32_2     = 0x0006 #  The 32-bit address relative to byte distance 2 from the relocation.
    const IMAGE_REL_AMD64_REL32_3     = 0x0007 #  The 32-bit address relative to byte distance 3 from the relocation.
    const IMAGE_REL_AMD64_REL32_4     = 0x0008 #  The 32-bit address relative to byte distance 4 from the relocation.
    const IMAGE_REL_AMD64_REL32_5     = 0x0009 #  The 32-bit address relative to byte distance 5 from the relocation.
    const IMAGE_REL_AMD64_SECTION     = 0x000A #  The 16-bit section index of the section that contains the target. This is used to support debugging information.
    const IMAGE_REL_AMD64_SECREL      = 0x000B #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_AMD64_SECREL7     = 0x000C #  A 7-bit unsigned offset from the base of the section that contains the target.
    const IMAGE_REL_AMD64_TOKEN       = 0x000D #  CLR tokens.
    const IMAGE_REL_AMD64_SREL32      = 0x000E #  A 32-bit signed span-dependent value emitted into the object.
    const IMAGE_REL_AMD64_PAIR        = 0x000F #  A pair that must immediately follow every span-dependent value.
    const IMAGE_REL_AMD64_SSPAN32     = 0x0010 #  A 32-bit signed span-dependent value that is applied at link time.
end

# # # ARM Relocations
@constants IMAGE_REL_ARM "IMAGE_REL_ARM_" begin
    const IMAGE_REL_ARM_ABSOLUTE      = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_ARM_ADDR32        = 0x0001 #  The 32-bit VA of the target.
    const IMAGE_REL_ARM_ADDR32NB      = 0x0002 #  The 32-bit RVA of the target.
    const IMAGE_REL_ARM_BRANCH24      = 0x0003 #  The most significant 24 bits of the signed 26-bit relative displacement of the target.  Applied to a B or BL instruction in ARM mode.
    const IMAGE_REL_ARM_BRANCH11      = 0x0004 #  The most significant 22 bits of the signed 23-bit relative displacement of the target.  Applied to a contiguous 16-bit B+BL pair in Thumb mode prior to ARMv7.
    const IMAGE_REL_ARM_TOKEN         = 0x0005 #  CLR tokens.
    const IMAGE_REL_ARM_BLX24         = 0x0008 #  The most significant 24 or 25 bits of the signed 26-bit relative displacement of the target.  Applied to an unconditional BL instruction in ARM mode.  The BL is transformed to a BLX during relocation if the target is in Thumb mode.
    const IMAGE_REL_ARM_BLX11         = 0x0009 #  The most significant 21 or 22 bits of the signed 23-bit relative displacement of the target.  Applied to a contiguous 16-bit B+BL pair in Thumb mode prior to ARMv7.  The BL is transformed to a BLX during relocation if the target is in ARM mode.
    const IMAGE_REL_ARM_SECTION       = 0x000E #  The 16-bit section index of the section that contains the target. This is used to support debugging information.
    const IMAGE_REL_ARM_SECREL        = 0x000F #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_ARM_MOV32A        = 0x0010 #  The 32-bit VA of the target.  Applied to a contiguous MOVW+MOVT pair in ARM mode.  The 32-bit VA is added to the existing value that is encoded in the immediate fields of the pair.
    const IMAGE_REL_ARM_MOV32T        = 0x0011 #  The 32-bit VA of the target.  Applied to a contiguous MOVW+MOVT pair in Thumb mode.  The 32-bit VA is added to the existing value that is encoded in the immediate fields of the pair.
    const IMAGE_REL_ARM_BRANCH20T     = 0x0012 #  The most significant 20 bits of the signed 21-bit relative displacement of the target.  Applied to a 32-bit conditional B instruction in Thumb mode.
    const IMAGE_REL_ARM_BRANCH24T     = 0x0014 #  The most significant 24 bits of the signed 25-bit relative displacement of the target.  Applied to a 32-bit unconditional B or BL instruction in Thumb mode.
    const IMAGE_REL_ARM_BLX23T        = 0x0015 #  The most significant 23 or 24 bits of the signed 25-bit relative displacement of the target.  Applied to a 32-bit BL instruction in Thumb mode.  The BL is transformed to a BLX during relocation if the target is in ARM mode.
end

# # # ARM64 Relocations
@constants IMAGE_REL_ARM64 "IMAGE_REL_ARM64_" begin
    const IMAGE_REL_ARM64_ABSOLUTE          = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_ARM64_ADDR32            = 0x0001 #  The 32-bit VA of the target.
    const IMAGE_REL_ARM64_ADDR32NB          = 0x0002 #  The 32-bit RVA of the target.
    const IMAGE_REL_ARM64_BRANCH26          = 0x0003 #  The 26-bit relative displacement to the target.
    const IMAGE_REL_ARM64_PAGEBASE_REL21    = 0x0004 #  The 21-bit page base of the target.
    const IMAGE_REL_ARM64_REL21             = 0x0005 #  The 21-bit relative displacement to the target.
    const IMAGE_REL_ARM64_PAGEOFFSET_12A    = 0x0006 #  The 12-bit page offset of the target address, used for instruction ADDS.
    const IMAGE_REL_ARM64_PAGEOFFSET_12L    = 0x0007 #  The 12-bit page offset of the target address, used for instruction LDR.
    const IMAGE_REL_ARM64_SECREL            = 0x0008 #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information.
    const IMAGE_REL_ARM64_SECREL_LOW12A     = 0x0009 #  The low 12-bit offset of the target from the beginning of its section. This is used for static thread local storage and for instruction ADDS.
    const IMAGE_REL_ARM64_SECREL_HIGH12A    = 0x000A #  The 12-bit (bit 12 to bit 23) offset of the target from the beginning of its section. This is used for static thread local storage and for instruction ADDS.
    const IMAGE_REL_ARM64_SECREL_LOW12L     = 0x000B #  The low 12-bit offset of the target from the beginning of its section. This is used for static thread local storage and for instruction LDR.
    const IMAGE_REL_ARM64_TOKEN             = 0x000C #  CLR token.
    const IMAGE_REL_ARM64_SECTION           = 0x000D #  The 16-bit section index of the section that contains the target. This is used to support debugging information.
    const IMAGE_REL_ARM64_ADDR64            = 0x000E #  The 64-bit VA of the relocation target.
end

# # # Hitachi SuperH relocations
@constants IMAGE_REL_SUPERH "IMAGE_REL_" begin
    const IMAGE_REL_SH3_ABSOLUTE            = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_SH3_DIRECT16            = 0x0001 #  A reference to the 16-bit location that contains the VA of the target symbol.
    const IMAGE_REL_SH3_DIRECT32            = 0x0002 #  The 32-bit VA of the target symbol.
    const IMAGE_REL_SH3_DIRECT8             = 0x0003 #  A reference to the 8-bit location that contains the VA of the target symbol.
    const IMAGE_REL_SH3_DIRECT8_WORD        = 0x0004 #  A reference to the 8-bit instruction that contains the effective 16-bit VA of the target symbol.
    const IMAGE_REL_SH3_DIRECT8_LONG        = 0x0005 #  A reference to the 8-bit instruction that contains the effective 32-bit VA of the target symbol.
    const IMAGE_REL_SH3_DIRECT4             = 0x0006 #  A reference to the 8-bit location whose low 4 bits contain the VA of the target symbol.
    const IMAGE_REL_SH3_DIRECT4_WORD        = 0x0007 #  A reference to the 8-bit instruction whose low 4 bits contain the effective 16-bit VA of the target symbol.
    const IMAGE_REL_SH3_DIRECT4_LONG        = 0x0008 #  A reference to the 8-bit instruction whose low 4 bits contain the effective 32-bit VA of the target symbol.
    const IMAGE_REL_SH3_PCREL8_WORD         = 0x0009 #  A reference to the 8-bit instruction that contains the effective 16-bit relative offset of the target symbol.
    const IMAGE_REL_SH3_PCREL8_LONG         = 0x000A #  A reference to the 8-bit instruction that contains the effective 32-bit relative offset of the target symbol.
    const IMAGE_REL_SH3_PCREL12_WORD        = 0x000B #  A reference to the 16-bit instruction whose low 12 bits contain the effective 16-bit relative offset of the target symbol.
    const IMAGE_REL_SH3_STARTOF_SECTION     = 0x000C #  A reference to a 32-bit location that is the VA of the section that contains the target symbol.
    const IMAGE_REL_SH3_SIZEOF_SECTION      = 0x000D #  A reference to the 32-bit location that is the size of the section that contains the target symbol.
    const IMAGE_REL_SH3_SECTION             = 0x000E #  The 16-bit section index of the section that contains the target. This is used to support debugging information.
    const IMAGE_REL_SH3_SECREL              = 0x000F #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_SH3_DIRECT32_NB         = 0x0010 #  The 32-bit RVA of the target symbol.
    const IMAGE_REL_SH3_GPREL4_LONG         = 0x0011 #  GP relative.
    const IMAGE_REL_SH3_TOKEN               = 0x0012 #  CLR token.
    const IMAGE_REL_SHM_PCRELPT             = 0x0013 #  The offset from the current instruction in longwords. If the NOMODE bit is not set, insert the inverse of the low bit at bit 32 to select PTA or PTB.
    const IMAGE_REL_SHM_REFLO               = 0x0014 #  The low 16 bits of the 32-bit address.
    const IMAGE_REL_SHM_REFHALF             = 0x0015 #  The high 16 bits of the 32-bit address.
    const IMAGE_REL_SHM_RELLO               = 0x0016 #  The low 16 bits of the relative address.
    const IMAGE_REL_SHM_RELHALF             = 0x0017 #  The high 16 bits of the relative address.
    const IMAGE_REL_SHM_PAIR                = 0x0018 #  The relocation is valid only when it immediately follows a REFHALF, RELHALF, or RELLO relocation. The SymbolTableIndex field of the relocation contains a displacement and not an index into the symbol table.
    const IMAGE_REL_SHM_NOMODE              = 0x8000 #  The relocation ignores section mode.
end

# # # PowerPC Relocations
@constants IMAGE_REL_PPC "IMAGE_REL_PPC_" begin
    const IMAGE_REL_PPC_ABSOLUTE    = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_PPC_ADDR64      = 0x0001 #  The 64-bit VA of the target.
    const IMAGE_REL_PPC_ADDR32      = 0x0002 #  The 32-bit VA of the target.
    const IMAGE_REL_PPC_ADDR24      = 0x0003 #  The low 24 bits of the VA of the target. This is valid only when the target symbol is absolute and can be sign-extended to its original value.
    const IMAGE_REL_PPC_ADDR16      = 0x0004 #  The low 16 bits of the target’s VA.
    const IMAGE_REL_PPC_ADDR14      = 0x0005 #  The low 14 bits of the target’s VA. This is valid only when the target symbol is absolute and can be sign-extended to its original value.
    const IMAGE_REL_PPC_REL24       = 0x0006 #  A 24-bit PC-relative offset to the symbol’s location.
    const IMAGE_REL_PPC_REL14       = 0x0007 #  A 14-bit PC-relative offset to the symbol’s location.
    const IMAGE_REL_PPC_ADDR32NB    = 0x000A #  The 32-bit RVA of the target.
    const IMAGE_REL_PPC_SECREL      = 0x000B #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_PPC_SECTION     = 0x000C #  The 16-bit section index of the section that contains the target. This is used to support debugging information.
    const IMAGE_REL_PPC_SECREL16    = 0x000F #  The 16-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_PPC_REFHI       = 0x0010 #  The high 16 bits of the target’s 32-bit VA. This is used for the first instruction in a two-instruction sequence that loads a full address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that was taken from the location that is being relocated.
    const IMAGE_REL_PPC_REFLO       = 0x0011 #  The low 16 bits of the target’s VA.
    const IMAGE_REL_PPC_PAIR        = 0x0012 #  A relocation that is valid only when it immediately follows a REFHI or SECRELHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    const IMAGE_REL_PPC_SECRELLO    = 0x0013 #  The low 16 bits of the 32-bit offset of the target from the beginning of its section.
    const IMAGE_REL_PPC_GPREL       = 0x0015 #  The 16-bit signed displacement of the target relative to the GP register.
    const IMAGE_REL_PPC_TOKEN       = 0x0016 #  The CLR token.
end

# # # i386 Relocations
@constants IMAGE_REL_I386 "IMAGE_REL_I386_" begin
    const IMAGE_REL_I386_ABSOLUTE = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_I386_DIR16    = 0x0001 #  Not supported.
    const IMAGE_REL_I386_REL16    = 0x0002 #  Not supported.
    const IMAGE_REL_I386_DIR32    = 0x0006 #  The target’s 32-bit VA.
    const IMAGE_REL_I386_DIR32NB  = 0x0007 #  The target’s 32-bit RVA.
    const IMAGE_REL_I386_SEG12    = 0x0009 #  Not supported.
    const IMAGE_REL_I386_SECTION  = 0x000A #  The 16-bit section index of the section that contains the target. This is used to support debugging information.
    const IMAGE_REL_I386_SECREL   = 0x000B #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_I386_TOKEN    = 0x000C #  The CLR token.
    const IMAGE_REL_I386_SECREL7  = 0x000D #  A 7-bit offset from the base of the section that contains the target.
    const IMAGE_REL_I386_REL32    = 0x0014 #  The 32-bit relative displacement of the target. This supports the x86 relative branch and call instructions.
end

# # # IA64 Relocation
@constants IMAGE_REL_IA64 "IMAGE_REL_IA64_" begin
    const IMAGE_REL_IA64_ABSOLUTE     = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_IA64_IMM14        = 0x0001 #  The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM14 bundle. The relocation target must be absolute or the image must be fixed.
    const IMAGE_REL_IA64_IMM22        = 0x0002 #  The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM22 bundle. The relocation target must be absolute or the image must be fixed.
    const IMAGE_REL_IA64_IMM64        = 0x0003 #  The slot number of this relocation must be one (1). The relocation can be followed by an ADDEND relocation whose value is added to the target address before it is stored in all three slots of the IMM64 bundle.
    const IMAGE_REL_IA64_DIR32        = 0x0004 #  The target’s 32-bit VA. This is supported only for /LARGEADDRESSAWARE:NO images.
    const IMAGE_REL_IA64_DIR64        = 0x0005 #  The target’s 64-bit VA.
    const IMAGE_REL_IA64_PCREL21B     = 0x0006 #  The instruction is fixed up with the 25-bit relative displacement of the 16-bit aligned target. The low 4 bits of the displacement are zero and are not stored.
    const IMAGE_REL_IA64_PCREL21M     = 0x0007 #  The instruction is fixed up with the 25-bit relative displacement of the 16-bit aligned target. The low 4 bits of the displacement, which are zero, are not stored.
    const IMAGE_REL_IA64_PCREL21F     = 0x0008 #  The LSBs of this relocation’s offset must contain the slot number whereas the rest is the bundle address. The bundle is fixed up with the 25-bit relative displacement of the 16-bit aligned target. The low 4 bits of the displacement are zero and are not stored.
    const IMAGE_REL_IA64_GPREL22      = 0x0009 #  The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address and then a 22-bit GP-relative offset that is calculated and applied to the GPREL22 bundle.
    const IMAGE_REL_IA64_LTOFF22      = 0x000A #  The instruction is fixed up with the 22-bit GP-relative offset to the target symbol’s literal table entry. The linker creates this literal table entry based on this relocation and the ADDEND relocation that might follow.
    const IMAGE_REL_IA64_SECTION      = 0x000B #  The 16-bit section index of the section contains the target. This is used to support debugging information.
    const IMAGE_REL_IA64_SECREL22     = 0x000C #  The instruction is fixed up with the 22-bit offset of the target from the beginning of its section. This relocation can be followed immediately by an ADDEND relocation, whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
    const IMAGE_REL_IA64_SECREL64I    = 0x000D #  The slot number for this relocation must be one (1). The instruction is fixed up with the 64-bit offset of the target from the beginning of its section. This relocation can be followed immediately by an ADDEND relocation whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
    const IMAGE_REL_IA64_SECREL32     = 0x000E #  The address of data to be fixed up with the 32-bit offset of the target from the beginning of its section.
    const IMAGE_REL_IA64_DIR32NB      = 0x0010 #  The target’s 32-bit RVA.
    const IMAGE_REL_IA64_SREL14       = 0x0011 #  This is applied to a signed 14-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    const IMAGE_REL_IA64_SREL22       = 0x0012 #  This is applied to a signed 22-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    const IMAGE_REL_IA64_SREL32       = 0x0013 #  This is applied to a signed 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    const IMAGE_REL_IA64_UREL32       = 0x0014 #  This is applied to an unsigned 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    const IMAGE_REL_IA64_PCREL60X     = 0x0015 #  A 60-bit PC-relative fixup that always stays as a BRL instruction of an MLX bundle.
    const IMAGE_REL_IA64_PCREL60B     = 0x0016 #  A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MBB bundle with NOP.B in slot 1 and a 25-bit BR instruction (with the 4 lowest bits all zero and dropped) in slot 2.
    const IMAGE_REL_IA64_PCREL60F     = 0x0017 #  A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MFB bundle with NOP.F in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    const IMAGE_REL_IA64_PCREL60I     = 0x0018 #  A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MIB bundle with NOP.I in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    const IMAGE_REL_IA64_PCREL60M     = 0x0019 #  A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MMB bundle with NOP.M in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    const IMAGE_REL_IA64_IMMGPREL64   = 0x001a #  A 64-bit GP-relative fixup.
    const IMAGE_REL_IA64_TOKEN        = 0x001b #  A CLR token.
    const IMAGE_REL_IA64_GPREL32      = 0x001c #  A 32-bit GP-relative fixup.
    const IMAGE_REL_IA64_ADDEND       = 0x001F #  The relocation is valid only when it immediately follows one of the following relocations: IMM14, IMM22, IMM64, GPREL22, LTOFF22, LTOFF64, SECREL22, SECREL64I, or SECREL32. Its value contains the addend to apply to instructions within a bundle, not for data.
end

# # # MIPS Relocations
@constants IMAGE_REL_MIPS "IMAGE_REL_MIPS_" begin
    const IMAGE_REL_MIPS_ABSOLUTE     = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_MIPS_REFHALF      = 0x0001 #  The high 16 bits of the target’s 32-bit VA.
    const IMAGE_REL_MIPS_REFWORD      = 0x0002 #  The target’s 32-bit VA.
    const IMAGE_REL_MIPS_JMPADDR      = 0x0003 #  The low 26 bits of the target’s VA. This supports the MIPS J and JAL instructions.
    const IMAGE_REL_MIPS_REFHI        = 0x0004 #  The high 16 bits of the target’s 32-bit VA. This is used for the first instruction in a two-instruction sequence that loads a full address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    const IMAGE_REL_MIPS_REFLO        = 0x0005 #  The low 16 bits of the target’s VA.
    const IMAGE_REL_MIPS_GPREL        = 0x0006 #  A 16-bit signed displacement of the target relative to the GP register.
    const IMAGE_REL_MIPS_LITERAL      = 0x0007 #  The same as IMAGE_REL_MIPS_GPREL.
    const IMAGE_REL_MIPS_SECTION      = 0x000A #  The 16-bit section index of the section contains the target. This is used to support debugging information.
    const IMAGE_REL_MIPS_SECREL       = 0x000B #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_MIPS_SECRELLO     = 0x000C #  The low 16 bits of the 32-bit offset of the target from the beginning of its section.
    const IMAGE_REL_MIPS_SECRELHI     = 0x000D #  The high 16 bits of the 32-bit offset of the target from the beginning of its section. An IMAGE_REL_MIPS_PAIR relocation must immediately follow this one. The SymbolTableIndex of the PAIR relocation contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    const IMAGE_REL_MIPS_JMPADDR16    = 0x0010 #  The low 26 bits of the target’s VA. This supports the MIPS16 JAL instruction.
    const IMAGE_REL_MIPS_REFWORDNB    = 0x0022 #  The target’s 32-bit RVA.
    const IMAGE_REL_MIPS_PAIR         = 0x0025 #  The relocation is valid only when it immediately follows a REFHI or SECRELHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
end

# # # M32R Relocations
@constants IMAGE_REL_M32R "IMAGE_REL_M32R_" begin
    const IMAGE_REL_M32R_ABSOLUTE     = 0x0000 #  The relocation is ignored.
    const IMAGE_REL_M32R_ADDR32       = 0x0001 #  The target’s 32-bit VA.
    const IMAGE_REL_M32R_ADDR32NB     = 0x0002 #  The target’s 32-bit RVA.
    const IMAGE_REL_M32R_ADDR24       = 0x0003 #  The target’s 24-bit VA.
    const IMAGE_REL_M32R_GPREL16      = 0x0004 #  The target’s 16-bit offset from the GP register.
    const IMAGE_REL_M32R_PCREL24      = 0x0005 #  The target’s 24-bit offset from the program counter (PC), shifted left by 2 bits and sign-extended 
    const IMAGE_REL_M32R_PCREL16      = 0x0006 #  The target’s 16-bit offset from the PC, shifted left by 2 bits and sign-extended
    const IMAGE_REL_M32R_PCREL8       = 0x0007 #  The target’s 8-bit offset from the PC, shifted left by 2 bits and sign-extended
    const IMAGE_REL_M32R_REFHALF      = 0x0008 #  The 16 MSBs of the target VA.
    const IMAGE_REL_M32R_REFHI        = 0x0009 #  The 16 MSBs of the target VA, adjusted for LSB sign extension. This is used for the first instruction in a two-instruction sequence that loads a full 32-bit address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    const IMAGE_REL_M32R_REFLO        = 0x000A #  The 16 LSBs of the target VA.
    const IMAGE_REL_M32R_PAIR         = 0x000B #  The relocation must follow the REFHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    const IMAGE_REL_M32R_SECTION      = 0x000C #  The 16-bit section index of the section that contains the target. This is used to support debugging information.
    const IMAGE_REL_M32R_SECREL       = 0x000D #  The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    const IMAGE_REL_M32R_TOKEN        = 0x000E #  The CLR token.
end

const MachineRelocationMap = Dict(
    IMAGE_FILE_MACHINE_IA64 => IMAGE_REL_IA64,
    IMAGE_FILE_MACHINE_MIPS16 => IMAGE_REL_MIPS,
    IMAGE_FILE_MACHINE_MIPSFPU16 => IMAGE_REL_MIPS,
    IMAGE_FILE_MACHINE_MIPSFPU => IMAGE_REL_MIPS,
    IMAGE_FILE_MACHINE_M32R => IMAGE_REL_M32R,
    IMAGE_FILE_MACHINE_ARM64 => IMAGE_REL_ARM64,
    IMAGE_FILE_MACHINE_ARM => IMAGE_REL_ARM,
    IMAGE_FILE_MACHINE_SH3 => IMAGE_REL_SUPERH,
    IMAGE_FILE_MACHINE_SH3DSP => IMAGE_REL_SUPERH,
    IMAGE_FILE_MACHINE_SH4 => IMAGE_REL_SUPERH,
    IMAGE_FILE_MACHINE_SH5 => IMAGE_REL_SUPERH,
    IMAGE_FILE_MACHINE_AMD64 => IMAGE_REL_AMD64,
    IMAGE_FILE_MACHINE_POWERPC => IMAGE_REL_PPC,
    IMAGE_FILE_MACHINE_POWERPCFP => IMAGE_REL_PPC,
    IMAGE_FILE_MACHINE_AMD64 => IMAGE_REL_AMD64,
    IMAGE_FILE_MACHINE_I386 => IMAGE_REL_I386
)

# # # Type representations
@constants IMAGE_SYM_TYPE "IMAGE_SYM_TYPE_" begin
    const IMAGE_SYM_TYPE_NULL         = 0 # No type information or unknown base type. Microsoft tools use this setting
    const IMAGE_SYM_TYPE_VOID         = 1 # No valid type; used with void pointers and functions
    const IMAGE_SYM_TYPE_CHAR         = 2 # A character (signed byte)
    const IMAGE_SYM_TYPE_SHORT        = 3 # A 2-byte signed integer
    const IMAGE_SYM_TYPE_INT          = 4 # A natural integer type (normally 4 bytes in Windows)
    const IMAGE_SYM_TYPE_LONG         = 5 # A 4-byte signed integer
    const IMAGE_SYM_TYPE_FLOAT        = 6 # A 4-byte floating-point number
    const IMAGE_SYM_TYPE_DOUBLE       = 7 # An 8-byte floating-point number
    const IMAGE_SYM_TYPE_STRUCT       = 8 # A structure
    const IMAGE_SYM_TYPE_UNION        = 9 # A union
    const IMAGE_SYM_TYPE_ENUM         = 10 #  An enumerated type
    const IMAGE_SYM_TYPE_MOE          = 11 #  A member of enumeration (a specific value)
    const IMAGE_SYM_TYPE_BYTE         = 12 #  A byte; unsigned 1-byte integer
    const IMAGE_SYM_TYPE_WORD         = 13 #  A word; unsigned 2-byte integer
    const IMAGE_SYM_TYPE_UINT         = 14 #  An unsigned integer of natural size (normally, 4 bytes)
    const IMAGE_SYM_TYPE_DWORD        = 15 #  An unsigned 4-byte intege
end

@constants IMAGE_SYM_DTYPE "IMAGE_SYM_DTYPE_" begin
    const IMAGE_SYM_DTYPE_NULL        = 0 #  No derived type; the symbol is a simple scalar variable. 
    const IMAGE_SYM_DTYPE_POINTER     = 1 #  The symbol is a pointer to base type.
    const IMAGE_SYM_DTYPE_FUNCTION    = 2 #  The symbol is a function that returns a base type.
    const IMAGE_SYM_DTYPE_ARRAY       = 3 #  The symbol is an array of base type.
end

# # # Storage Class
@constants IMAGE_SYM_CLASS "IMAGE_SYM_CLASS_" begin
    const IMAGE_SYM_CLASS_END_OF_FUNCTION   = 0xFF   # A special symbol that represents the end of function, for debugging purposes.
    const IMAGE_SYM_CLASS_NULL              = 0      # No assigned storage class.
    const IMAGE_SYM_CLASS_AUTOMATIC         = 1      # The automatic (stack) variable. The Value field specifies the stack frame offset.
    const IMAGE_SYM_CLASS_EXTERNAL          = 2      # A value that Microsoft tools use for external symbols. The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0). If the section number is not zero, then the Value field specifies the offset within the section.
    const IMAGE_SYM_CLASS_STATIC            = 3      # The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
    const IMAGE_SYM_CLASS_REGISTER          = 4      # A register variable. The Value field specifies the register number.
    const IMAGE_SYM_CLASS_EXTERNAL_DEF      = 5      # A symbol that is defined externally.
    const IMAGE_SYM_CLASS_LABEL             = 6      # A code label that is defined within the module. The Value field specifies the offset of the symbol within the section.
    const IMAGE_SYM_CLASS_UNDEFINED_LABEL   = 7      # A reference to a code label that is not defined.
    const IMAGE_SYM_CLASS_MEMBER_OF_STRUCT  = 8      # The structure member. The Value field specifies the nth member.
    const IMAGE_SYM_CLASS_ARGUMENT          = 9      # A formal argument (parameter) of a function. The Value field specifies the nth argument.
    const IMAGE_SYM_CLASS_STRUCT_TAG        = 10     #   The structure tag-name entry.
    const IMAGE_SYM_CLASS_MEMBER_OF_UNION   = 11     #   A union member. The Value field specifies the nth member.
    const IMAGE_SYM_CLASS_UNION_TAG         = 12     #   The Union tag-name entry.
    const IMAGE_SYM_CLASS_TYPE_DEFINITION   = 13     #   A Typedef entry.
    const IMAGE_SYM_CLASS_UNDEFINED_STATIC  = 14     #   A static data declaration.
    const IMAGE_SYM_CLASS_ENUM_TAG          = 15     #   An enumerated type tagname entry.
    const IMAGE_SYM_CLASS_MEMBER_OF_ENUM    = 16     #   A member of an enumeration. The Value field specifies the nth member.
    const IMAGE_SYM_CLASS_REGISTER_PARAM    = 17     #   A register parameter.
    const IMAGE_SYM_CLASS_BIT_FIELD         = 18     #   A bit-field reference. The Value field specifies the nth bit in the bit field.
    const IMAGE_SYM_CLASS_BLOCK             = 100    #    A .bb (beginning of block) or .eb (end of block) record. The Value field is the relocatable address of the code location.
    const IMAGE_SYM_CLASS_FUNCTION          = 101    # A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf), end function (.ef), and lines in function (.lf). For .lf records, the Value field gives the number of source lines in the function. For .ef records, the Value field gives the size of the function code.
    const IMAGE_SYM_CLASS_END_OF_STRUCT     = 102    # An end-of-structure entry.
    const IMAGE_SYM_CLASS_FILE              = 103    # A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record. The symbol is followed by auxiliary records that name the file.
    const IMAGE_SYM_CLASS_SECTION           = 104    # A definition of a section (Microsoft tools use STATIC storage class instead).
    const IMAGE_SYM_CLASS_WEAK_EXTERNAL     = 105    # A weak external. For more information, see section 5.5.3, “Auxiliary Format 3: Weak Externals.”
    const IMAGE_SYM_CLASS_CLR_TOKEN         = 107    # A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token. For more information, see section 5.5.7, “CLR Token Definition (Object Only).”
end

# # # COMDAT Section
const IMAGE_COMDAT_SELECT_NODUPLICATES  = 1 #   If this symbol is already defined, the linker issues a “multiply defined symbol” error.
const IMAGE_COMDAT_SELECT_ANY           = 2 #   Any section that defines the same COMDAT symbol can be linked; the rest are removed.
const IMAGE_COMDAT_SELECT_SAME_SIZE     = 3 #   The linker chooses an arbitrary section among the definitions for this symbol. If all definitions are not the same size, a “multiply defined symbol” error is issued.
const IMAGE_COMDAT_SELECT_EXACT_MATCH   = 4 #   The linker chooses an arbitrary section among the definitions for this symbol. If all definitions do not match exactly, a “multiply defined symbol” error is issued.
const IMAGE_COMDAT_SELECT_ASSOCIATIVE   = 5 #   The section is linked if a certain other COMDAT section is linked. This other section is indicated by the Number field of the auxiliary symbol record for the section definition. This setting is useful for definitions that have components in multiple sections (for example, code in one and data in another), but where all must be linked or discarded as a set. The other section with which this section is associated must be a COMDAT section; it cannot be another associative COMDAT section (that is, the other section cannot have IMAGE_COMDAT_SELECT_ASSOCIATIVE set).
const IMAGE_COMDAT_SELECT_LARGEST       = 6 #   The linker chooses the largest definition from among all of the definitions for this symbol. If multiple definitions have this size, the choice between them is arbitrary.

# # # Win Cert
const WIN_CERT_REVISION_1_0 = 0x100  # Version 1, legacy version of the Win_Certificate structure. It is supported only for purposes of verifying legacy Authenticode signatures
const WIN_CERT_REVISION_2_0 = 0x200  # Version 2 is the current version of the Win_Certificate structure. 

const WIN_CERT_TYPE_X509                = 0x0001 # b_certificate contains an X.509 Certificate  (Not Supported)
const WIN_CERT_TYPE_PKCS_SIGNED_DATA    = 0x0002 # b_certificate contains a PKCS#7 SignedData structure
const WIN_CERT_TYPE_RESERVED_1          = 0x0003 # Reserved 
const WIN_CERT_TYPE_TS_STACK_SIGNED     = 0x0004 # Terminal Server Protocol Stack Certificate signing (Not Supported)

# # # Debug Type
const IMAGE_DEBUG_TYPE_UNKNOWN          = 0  # An unknown value that is ignored by all tools.
const IMAGE_DEBUG_TYPE_COFF             = 1  # The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
const IMAGE_DEBUG_TYPE_CODEVIEW         = 2  # The Visual C++ debug information. 
const IMAGE_DEBUG_TYPE_FPO              = 3  # The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
const IMAGE_DEBUG_TYPE_MISC             = 4  # The location of DBG file.
const IMAGE_DEBUG_TYPE_EXCEPTION        = 5  # A copy of .pdata section.
const IMAGE_DEBUG_TYPE_FIXUP            = 6  # Reserved.
const IMAGE_DEBUG_TYPE_OMAP_TO_SRC      = 7  # The mapping from an RVA in image to an RVA in source image.
const IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    = 8  # The mapping from an RVA in source image to an RVA in image.
const IMAGE_DEBUG_TYPE_BORLAND          = 9  # Reserved for Borland.
const IMAGE_DEBUG_TYPE_RESERVED10       = 10 # Reserved.
const IMAGE_DEBUG_TYPE_CLSID            = 11 # Reserved.

# # # Base Relocations
const IMAGE_REL_BASED_ABSOLUTE          = 0  # The base relocation is skipped. This type can be used to pad a block.
const IMAGE_REL_BASED_HIGH              = 1  # The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
const IMAGE_REL_BASED_LOW               = 2  # The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word. 
const IMAGE_REL_BASED_HIGHLOW           = 3  # The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
const IMAGE_REL_BASED_HIGHADJ           = 4  # The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
const IMAGE_REL_BASED_MIPS_JMPADDR      = 5  # For MIPS machine types, the base relocation applies to a MIPS jump instruction.
const IMAGE_REL_BASED_ARM_MOV32A        = 5  # For ARM machine types, the base relocation applies the difference to the 32-bit value encoded in the immediate fields of a contiguous MOVW+MOVT pair in ARM mode at offset.
#                                       = 6  # Reserved, must be zero.
const IMAGE_REL_BASED_ARM_MOV32T        = 7  # The base relocation applies the difference to the 32-bit value encoded in the immediate fields of a contiguous MOVW+MOVT pair in Thumb mode at offset.
const IMAGE_REL_BASED_MIPS_JMPADDR16    = 9  # The base relocation applies to a MIPS16 jump instruction.
const IMAGE_REL_BASED_DIR64             = 10 #The base relocation applies the difference to the 64-bit field at offset.
