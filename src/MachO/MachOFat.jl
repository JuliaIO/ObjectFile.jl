export MachOFatArch, MachOFatHeader, FatMachOHandle

abstract type MachOFatArchitecture end

@io struct MachOFatArch32 <: MachOFatArchitecture
    cputype::UInt32
    cpusubtype::UInt32
    offset::UInt32
    size::UInt32
    align::UInt32
end

@io struct MachOFatArch64 <: MachOFatArchitecture
    cputype::UInt64
    cpusubtype::UInt64
    offset::UInt64
    size::UInt64
    align::UInt32
    reserved::UInt32
end

struct MachOFatHeader{H <: ObjectHandle} <: MachOHeader{H}
    magic::UInt32
    archs::Vector{MachOFatArchitecture}
end

function StructIO.unpack(io::IO, T::Type{<:MachOFatHeader}, endian::Symbol)
    magic = read(io, UInt32)
    nfats = unpack(io, UInt32, endian)
    archtyp = macho_is64bit(magic) ? MachOFatArch64 : MachOFatArch32
    archs = Vector{archtyp}(undef, nfats)
    for i = 1:nfats
        archs[i] = unpack(io, archtyp, endian)
    end
    T(magic, archs)
end

function show(io::IO, header::MachOFatHeader)
    println(io, "MachOFatHeader Header")
    println(io, "  architectures: $(length(header.archs))")
end

struct FatMachOHandle{T <: IO} <: AbstractMachOHandle{T}
    # Backing IO and start point within the IOStream of this MachO object
    io::T
    start::Int64

    # The parsed-out header of the MachO object
    header::MachOFatHeader

    # The path of the file this was created with, if it exists
    path::String
end

function readmeta(io::IO,::Type{FatMachOHandle})
    start = position(io)
    header_type, endianness = readmeta(io, AbstractMachOHandle)
    (header_type <: MachOFatHeader) || throw(MagicMismatch("Binary is not fat"))

    # Unpack the header
    header = unpack(io, header_type, endianness)
    return FatMachOHandle(io, start, header, path(io))
end

# Iteration
keys(h::FatMachOHandle) = 1:length(h)
iterate(h::FatMachOHandle, idx=1) = idx > length(h) ? nothing : (h[idx], idx+1)
lastindex(h::FatMachOHandle) = lastindex(h.header.archs)
length(h::FatMachOHandle) = length(h.header.archs)
eltype(::Type{<:FatMachOHandle}) = MachOHandle
function getindex(h::FatMachOHandle, idx)
    seek(h.io, h.start + h.header.archs[idx].offset)
    only(readmeta(h.io, MachOHandle))
end

function show(io::IO, oh::FatMachOHandle)
    print(io, "$(format_string(typeof(oh))) Fat Handle")
end
