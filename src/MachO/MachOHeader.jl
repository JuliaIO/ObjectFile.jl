export MachHeader, MachHeader32, MachHeader64

import Base: show

"""
    MachHeader

Mach-O Header type, containing metadata about the Mach object itself, such as
its CPU target, the number of Load Commands within the file, etc...
"""
abstract type MachOHeader{H <: ObjectHandle} end

@io struct MachOHeader32{H <: ObjectHandle} <: MachOHeader{H}
    magic::UInt32
    cputype::UInt32
    cpusubtype::UInt32
    filetype::UInt32
    ncmds::UInt32
    sizeofcmds::UInt32
    flags::UInt32
end

@io struct MachOHeader64{H <: ObjectHandle} <: MachOHeader{H}
    magic::UInt32
    cputype::UInt32
    cpusubtype::UInt32
    filetype::UInt32
    ncmds::UInt32
    sizeofcmds::UInt32
    flags::UInt32
    reserved::UInt32
end

"""
    macho_header_type(magic::UInt32)

Given the `magic` field from a Mach-O file header, return the type of the
Mach-O header.
"""
function macho_header_type(magic::UInt32)
    if magic in (MH_MAGIC, MH_CIGAM)
        return MachOHeader32{MachOHandle}
    elseif magic in (MH_MAGIC_64, MH_CIGAM_64)
        return MachOHeader64{MachOHandle}
    elseif magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64, FAT_MAGIC_METAL, FAT_CIGAM_METAL)
        return MachOFatHeader{MachOHandle}
    elseif magic in (METALLIB_MAGIC,)
        return MetallibHeader{MachOHandle}
    else
        throw(MagicMismatch("Invalid Magic (0x$(string(magic, base=16, pad=8)))!"))
    end
end

"""
    macho_is64bit(magic::UInt32)

Given the `magic` field from a Mach-O file header, return the bitwidth of the
Mach-O header.
"""
function macho_is64bit(magic::UInt32)
    if magic in (MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC_64, FAT_CIGAM_64)
        return true
    elseif magic in (MH_MAGIC, MH_CIGAM, FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_METAL, FAT_CIGAM_METAL, METALLIB_MAGIC)
        return false
    else
        throw(MagicMismatch("Invalid Magic (0x$(string(magic, base=16, pad=8)))!"))
    end
end

"""
    macho_endianness(magic::UInt32)

Given the `magic` field from a Mach-O file header, return the endianness of the
Mach-O header.
"""
function macho_endianness(magic::UInt32)
    if magic in (MH_CIGAM, MH_CIGAM_64, FAT_CIGAM, FAT_CIGAM_METAL)
        return :BigEndian
    elseif magic in (MH_MAGIC, MH_MAGIC_64, FAT_MAGIC, FAT_MAGIC_METAL, METALLIB_MAGIC)
        return :LittleEndian
    else
        throw(MagicMismatch("Invalid Magic (0x$(string(magic, base=16, pad=8)))!"))
    end
end

function show(io::IO, header::MachOHeader)
    println(io, "MachO Header")
    println(io, "  CPU Type ", header.cputype)
    println(io, "  CPU Subtype ", header.cpusubtype)
    println(io, "  File Type ", header.filetype)
    println(io, "  Number of load commands ", header.ncmds)
    println(io, "  Flags ", header.flags)
end
