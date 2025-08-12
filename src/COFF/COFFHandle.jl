export COFFHandle

"""
    COFFHandle

An `ObjectHandle` subclass for COFF files, this is the primary object by which
client applications will interact with COFF files.
"""
struct COFFHandle{T<:IO} <: ObjectHandle
    # Backing IOS and start point within the IOStream of this COFF object
    io::T
    start::Int64

    # The parsed-out header of the COFF object
    header::COFFHeader

    # The location of the header (because of MZ confusion, we must store this)
    header_offset::UInt32

    # The "Optional" header, which isn't actually optional
    opt_header::COFFOptionalHeader

    # The path of the file this was created with
    path::String
end

## Define creation methods
function readmeta(io::IO, ::Type{H}) where {H <: COFFHandle}
    # This is the magic that we know we must find
    PE_magic = UInt8['P','E','\0','\0']
    MZ_magic = UInt8['M','Z']

    # Save the starting position of `io`
    start = position(io)

    # Check to see if this is an 'MZ' file; if it is, we have to jump forward
    # into the file a bit to get to the PE header
    magic = [read(io, UInt8) for idx in 1:2]
    if all(magic .== MZ_magic)
        # Skip ahead to the PE header offset
        skip(io, 58)
        header_offset = read(io, UInt32)
        seek(io, start + header_offset)
    else
        # If it's not, assume the PE header starts at the beginning of the file
        skip(io, -2)
    end

    magic = [read(io, UInt8) for idx in 1:4]
    if any(magic .!= PE_magic)
        msg = """
        Magic Number 0x$(join(string.(magic, base=16, pad=2),"")) does not match expected PE
        magic number 0x$(join(string.(PE_magic, base=16, pad=2),""))
        """
        throw(MagicMismatch(replace(strip(msg), "\n" => " ")))
    end

    # Read the PE header and place the header offset just past the PE_magic
    header_offset = UInt32(position(io) - start)
    header = unpack(io, COFFHeader)

    # Next, read the optional header
    opt_header = read(io, COFFOptionalHeader)

    # Construct our COFFHandle, pilfering the filename from the IOStream
    return [COFFHandle(io, Int64(start), header, header_offset, opt_header, path(io))]
end


## IOStream-like operations:
startaddr(oh::COFFHandle) = oh.start
iostream(oh::COFFHandle) = oh.io

## Format-specific properties:
header(oh::COFFHandle) = oh.header
Platform(oh::COFFHandle) = Platform(coff_machine_to_arch(oh.header.Machine), "windows")
endianness(oh::COFFHandle) = coff_header_endianness(header(oh))
is64bit(oh::COFFHandle) = coff_header_is64bit(header(oh))
isrelocatable(oh::COFFHandle) = isrelocatable(header(oh))
isexecutable(oh::COFFHandle) = isexecutable(header(oh))
islibrary(oh::COFFHandle) = islibrary(header(oh))
isdynamic(oh::COFFHandle) = !isempty(findall(Sections(oh), [".idata"]))
mangle_section_name(oh::COFFHandle, name::AbstractString) = string(".", name)
function mangle_symbol_name(oh::COFFHandle, name::AbstractString)
    # sob
    if is64bit(oh)
        return name
    else
        return string("_", name)
    end
end
format_string(::Type{H}) where {H <: COFFHandle} = "COFF"

## Section information
function section_header_offset(oh::COFFHandle)
    h = header(oh)
    return oh.header_offset + sizeof(COFFHeader) + h.SizeOfOptionalHeader
end
section_header_size(oh::COFFHandle) = sizeof(section_header_type(oh))
section_header_type(oh::H) where {H <: COFFHandle} = COFFSection{H}

### Symbol properties
symtab_entry_offset(oh::COFFHandle) = header(oh).PointerToSymbolTable
symtab_entry_size(oh::COFFHandle) = packed_sizeof(symtab_entry_type(oh))
symtab_entry_type(oh::H) where {H <: COFFHandle} = COFFSymtabEntry{H}

### Strtab properties
function strtab_offset(oh::H) where {H <: COFFHandle}
    h = header(oh)
    return h.PointerToSymbolTable + h.NumberOfSymbols*symtab_entry_size(oh)
end

### Misc. stuff
path(oh::COFFHandle) = oh.path
