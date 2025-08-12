# Export Datatypes
export ELFHandle

# Import Base methods
import Base: getindex


"""
    ELFHandle

An `ObjectHandle` subclass for ELF files, this is the primary object by which
client applications will interact with ELF files.
"""
struct ELFHandle{T<:IO} <: ObjectHandle
    # Backing IOS and start point within the IOStream of this ELF object
    io::T
    start::Int64

    # Elf Internal data such as endianness, version, OS ABI, etc...
    ei::ELFInternal

    # The parsed-out header of the ELF object
    header::ELFHeader

    # The path of the file this was created with
    path::String
end

## Define creation methods
function readmeta(io::IO, ::Type{H}) where {H <: ELFHandle}
    # This is the magic that we know we must find
    elven_magic = UInt8['\177', 'E', 'L', 'F']

    # Save the starting position of `io`
    start = position(io)

    # Check for magic bytes
    magic = [read(io, UInt8) for idx in 1:4]
    if any(magic .!= elven_magic)
        msg = """
        Magic Number 0x$(join(string.(magic, base=16, pad=2),"")) does not match expected ELF
        magic number 0x$(join(string.(elven_magic, base=16, pad=2),""))
        """
        throw(MagicMismatch(replace(strip(msg), "\n" => " ")))
    end

    # Read the ELF Internal data, then skip its padding
    ei = unpack(io, ELFInternal)
    skip(io, 7)

    # Build different Header objects for 32 or 64-bit ELF
    header_type = elf_internal_is64bit(ei) ? ELFHeader64{H} : ELFHeader32{H}

    # Unpack the header, but pretend we didn't by rewinding `io`
    header = unpack(io, header_type, elf_internal_endianness(ei))
    seek(io, start)

    # Construct our ELFHandle, pilfering the filename from the IOStream
    return [ELFHandle(io, Int64(start), ei, header, path(io))]
end


## IOStream-like operations:
startaddr(oh::ELFHandle) = oh.start
iostream(oh::ELFHandle) = oh.io

# We don't try to inspect dynamic libraries to figure out if this is a glibc or musl dynamic object
function strip_libc_tag(p::Platform)
    delete!(tags(p), "libc")
    return p
end

## Format-specific properties:
header(oh::ELFHandle) = oh.header
function Platform(oh::ELFHandle)
    arch = elf_machine_to_arch(oh.header.e_machine)
    if oh.ei.osabi == ELFOSABI_LINUX || oh.ei.osabi == ELFOSABI_NONE
        return strip_libc_tag(Platform(arch, "linux"))
    elseif oh.ei.osabi == ELFOSABI_FREEBSD
        return Platform(arch, "freebsd")
    else
        throw(ArgumentError("Unknown ELF OSABI $(oh.ei.osabi)"))
    end
end
endianness(oh::ELFHandle) = elf_internal_endianness(oh.ei)
is64bit(oh::ELFHandle) = elf_internal_is64bit(oh.ei)
isrelocatable(oh::ELFHandle) = header(oh).e_type == ET_REL
isexecutable(oh::ELFHandle) = header(oh).e_type == ET_EXEC
islibrary(oh::ELFHandle) = header(oh).e_type == ET_DYN
isdynamic(oh::ELFHandle) = !isempty(findall(Sections(oh), ".dynamic"))
mangle_section_name(oh::ELFHandle, name::AbstractString) = string(".", name)
mangle_symbol_name(oh::ELFHandle, name::AbstractString) = name
format_string(::Type{H}) where {H <: ELFHandle} = "ELF"

# Section information
section_header_offset(oh::ELFHandle) = header(oh).e_shoff
section_header_size(oh::ELFHandle) = header(oh).e_shentsize
function section_header_type(oh::H) where {H <: ELFHandle}
    if is64bit(oh)
        return ELFSection64{H}
    else
        return ELFSection32{H}
    end
end


# Segment information (Note this is NOT a part of the generic ObjectFile API,
# this is an ELF-only extension)
"""
    segment_header_offset(oh::ELFHandle)

Return the offset of the segment header table within the given ELF object.
"""
segment_header_offset(oh::ELFHandle) = header(oh).e_phoff

"""
    segment_header_offset(oh::ELFHandle)

Return the size of a segment header within the given ELF object.
"""
segment_header_size(oh::ELFHandle) = header(oh).e_phentsize

"""
    segment_header_type(oh::ELFHandle)

Return the type of a segment header within the given ELF object.  E.g. within a
64-bit ELF object, this will return `ELFSegment64`.
"""
function segment_header_type(oh::H) where {H <: ELFHandle}
    if is64bit(oh)
        return ELFSegment64{H}
    else
        return ELFSegment32{H}
    end
end


# Symbol information
symtab_entry_offset(oh::ELFHandle) = section_offset(Symbols(oh).section_ref)
symtab_entry_size(oh::ELFHandle) = sizeof(symtab_entry_type(oh))
function symtab_entry_type(oh::H) where {H <: ELFHandle}
    if is64bit(oh)
        return ELFSymtabEntry64{H}
    else
        return ELFSymtabEntry32{H}
    end
end

# Dynamic Linkage information
function dyn_entry_type(oh::H) where {H <: ELFHandle}
    if is64bit(oh)
        return ELFDynEntry64{H}
    else
        return ELFDynEntry32{H}
    end
end


## Misc. operations
path(oh::ELFHandle) = oh.path
