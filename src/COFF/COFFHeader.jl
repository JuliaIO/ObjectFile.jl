export COFFHeader

import Base: show

@io struct COFFHeader
    Machine::UInt16
    NumberOfSections::UInt16
    TimeDateStamp::UInt32
    PointerToSymbolTable::UInt32
    NumberOfSymbols::UInt32
    SizeOfOptionalHeader::UInt16
    Characteristics::UInt16
end

function coff_header_is64bit(h::COFFHeader)
    wide_machines = [
        IMAGE_FILE_MACHINE_AMD64,
        IMAGE_FILE_MACHINE_ARM64,
        IMAGE_FILE_MACHINE_ARM64EC,
        IMAGE_FILE_MACHINE_ARM64X,
        IMAGE_FILE_MACHINE_IA64,
    ]
    return h.Machine in wide_machines
end

function coff_header_endianness(h::COFFHeader)
    # We don't ever process :BigEndian COFF files; but if we did, we'd probably
    # design a check against `h.Machine` here.
    return :LittleEndian
end

isexecutable(h::COFFHeader) = (h.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0
islibrary(h::COFFHeader) = (h.Characteristics & IMAGE_FILE_DLL) != 0
isrelocatable(h::COFFHeader) = !isexecutable(h) && !islibrary(h)

num_sections(h::COFFHeader) = h.NumberOfSections
num_symbols(h::COFFHeader) = h.NumberOfSymbols

function show(io::IO, header::COFFHeader)
    println(io, "COFF Header")
    println(io, "  Machine ", header.Machine)
    println(io, "  Number of Sections ", header.NumberOfSections)
    println(io, "  Time Date Stamp ", header.TimeDateStamp)
    println(io, "  Number of Symbols ", header.NumberOfSymbols)
end