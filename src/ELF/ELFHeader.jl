export ELFHeader, ELFHeader32, ELFHeader64

import Base: show

"""
    ELFHeader

ELF Header type, containing metadata about the ELF object itself, such as its
type, offsets for the Program and Section headers, the number of other header
entries, etc...
"""
abstract type ELFHeader{H <: ObjectHandle} end
@io struct ELFHeader32{H <: ObjectHandle} <: ELFHeader{H}
    e_type::UInt16
    e_machine::UInt16
    e_version::UInt32
    e_entry::UInt32
    e_phoff::UInt32
    e_shoff::UInt32
    e_flags::UInt32
    e_ehsize::UInt16
    e_phentsize::UInt16
    e_phnum::UInt16
    e_shentsize::UInt16
    e_shnum::UInt16
    e_shstrndx::UInt16
end
@io struct ELFHeader64{H <: ObjectHandle} <: ELFHeader{H}
    e_type::UInt16
    e_machine::UInt16
    e_version::UInt32
    e_entry::UInt64
    e_phoff::UInt64
    e_shoff::UInt64
    e_flags::UInt32
    e_ehsize::UInt16
    e_phentsize::UInt16
    e_phnum::UInt16
    e_shentsize::UInt16
    e_shnum::UInt16
    e_shstrndx::UInt16
end

function filetype(e_type)
    if haskey(ET_TYPES, e_type)
        return ET_TYPES[e_type]
    end
    return string("Unknown (0x",string(e_type, base=16),")")
end


function machinetype(e_machine)
    if haskey(EM_MACHINES, e_machine)
        return EM_MACHINES[e_machine]
    end
    return string("Unknown (0x",string(e_machine, base=16),")")
end

function elf_machine_to_arch(machine::UInt16)
    if machine ∈ (EM_386,)
        return "i686"
    elseif machine ∈ (EM_IA_64, EM_X86_64)
        return "x86_64"
    elseif machine ∈ (EM_ARM,)
        return "armv7l"
    elseif machine ∈ (EM_AARCH64,)
        return "aarch64"
    elseif machine ∈ (EM_PPC64,)
        return "ppc64le"
    elseif machine ∈ (EM_RISCV,)
        return "riscv64"
    end
end


function show(io::IO, header::ELFHeader)
    println(io, "ELF Header")
    println(io, "  Type ", filetype(header.e_type))
    println(io, "  Machine ", machinetype(header.e_machine))
    # Skip e_version (not particularly useful)
    println(io, "  Entrypoint ", "0x", string(header.e_entry, base=16))
    println(io, "  PH Offset ", "0x", string(header.e_phoff, base=16))
    println(io, "  SH Offset ", "0x", string(header.e_shoff, base=16))
    # Skip flags
    println(io, "  Header Size ", "0x", string(header.e_ehsize, base=16))
    println(io, "  PH Entry Size ", "0x", string(header.e_phentsize, base=16))
    println(io, "  PH Entry Count ", string(header.e_phnum, base=10))
    println(io, "  SH Entry Size ", "0x", string(header.e_shentsize, base=16))
    println(io, "  SH Entry Count ", string(header.e_shnum, base=10))
    println(io, "  Strtab Index ", string(header.e_shstrndx, base=10))
end
