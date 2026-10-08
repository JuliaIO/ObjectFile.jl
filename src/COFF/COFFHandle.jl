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

    # The "Optional" header, which isn't actually optional for images, but is
    # absent from object files
    opt_header::Union{Nothing,COFFOptionalHeader}

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
    magic = read(io, 2)
    if magic == MZ_magic
        # Skip ahead to the PE header offset
        skip(io, 58)
        header_offset = read(io, UInt32)
        seek(io, start + header_offset)
    else
        # If it's not, the PE header may start at the beginning of the file
        seek(io, start)
    end

    magic = read(io, 4)
    if magic != PE_magic
        # An object file has no PE header (nor an MZ stub), it starts directly
        # with its COFF header.
        if magic[1:min(2, end)] != MZ_magic
            seek(io, start)
            header = read_object_header(io)
            if header !== nothing
                return [COFFHandle(io, Int64(start), header, UInt32(0), nothing, path(io))]
            end
        end

        msg = """
        Magic Number 0x$(join(string.(magic, base=16, pad=2),"")) does not match expected PE
        magic number 0x$(join(string.(PE_magic, base=16, pad=2),"")), nor is this a COFF object
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

"""
    read_object_header(io::IO)

Read the `COFFHeader` of an object file (e.g. `foo.obj`) at the current position
of `io`, returning `nothing` if it does not look like one.  Object files have no
magic number beyond the `Machine` field of their header, so we check that the
rest of the header is consistent with an object file of that size.
"""
function read_object_header(io::IO)
    start = position(io)
    header = unpack(io, COFFHeader)
    # Find out how much room there is for this object, at most
    seekend(io)
    available = position(io) - start
    seek(io, start)

    if !haskey(IMAGE_FILE_MACHINE, header.Machine) || header.Machine == IMAGE_FILE_MACHINE_UNKNOWN
        return nothing
    end
    # Only images have an optional header, or are executables/DLLs
    if header.SizeOfOptionalHeader != 0 ||
       (header.Characteristics & (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL)) != 0
        return nothing
    end
    # The section and symbol tables must fit within the object
    if sizeof(COFFHeader) + header.NumberOfSections * packed_sizeof(COFFSection{COFFHandle}) > available
        return nothing
    end
    if header.PointerToSymbolTable != 0 &&
       header.PointerToSymbolTable + header.NumberOfSymbols * packed_sizeof(COFFSymtabEntry{COFFHandle}) > available
        return nothing
    end
    return header
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
    # sob; only 32-bit x86 prefixes C symbols with an underscore
    if header(oh).Machine == IMAGE_FILE_MACHINE_I386
        return string("_", name)
    else
        return name
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
