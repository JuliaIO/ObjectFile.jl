module Archive

using ObjectFile, StructIO
import ObjectFile: readmeta, path
import Base: show, read, getindex, iterate, length, keys, firstindex, lastindex, eltype

export ArchiveHandle, ArchiveMember, ArchiveMemberHeader, archive_kind, isthin

# Each archive starts with one of these, followed by a sequence of members
const AR_MAGIC = b"!<arch>\n"
const AR_THIN_MAGIC = b"!<thin>\n"

# Each member starts with an `ArchiveMemberHeader` ending in `AR_FMAG`
const AR_FMAG = b"`\n"

# The members that index an archive rather than being a part of it, by kind of
# archive (see `archive_kind()`)
const GNU_SYMTAB = "/"
const GNU_SYMTAB64 = "/SYM64/"
const GNU_NAMETAB = "//"
const COFF_EC_SYMTAB = "/<ECSYMBOLS>/"
const BSD_SYMTAB = ("__.SYMDEF", "__.SYMDEF SORTED")
const BSD_SYMTAB64 = ("__.SYMDEF_64", "__.SYMDEF_64 SORTED")
const BSD_LONG_NAME_PREFIX = "#1/"

"""
    ArchiveMemberHeader

The header of a member of a static archive (`ar_hdr`), made of space-padded
ASCII fields.  `name` is the member's name, as encoded by the kind of archive (see
`archive_kind()`), `mode` is in octal, and the other fields are in decimal.
"""
@io struct ArchiveMemberHeader
    name::NTuple{16,UInt8}
    mtime::NTuple{12,UInt8}
    uid::NTuple{6,UInt8}
    gid::NTuple{6,UInt8}
    mode::NTuple{8,UInt8}
    size::NTuple{10,UInt8}
    fmag::NTuple{2,UInt8}
end align_packed

field_string(field::NTuple{N,UInt8}) where {N} = rstrip(String(collect(field)), ' ')

# Parse an integer field of a member header, which may be blank
function parse_field(field::NTuple{N,UInt8}, base::Int = 10) where {N}
    s = field_string(field)
    return isempty(s) ? 0 : parse(Int64, s; base)
end

"""
    ArchiveMember

A member of a static archive, as listed in an [`ArchiveHandle`](@ref).  `offset`
is the location of the member's data relative to the start of the archive, or
`nothing` for members of a thin archive, whose data lives in the file `name`
(relative to the archive).
"""
struct ArchiveMember
    name::String
    offset::Union{Nothing,Int64}
    size::Int64
    mtime::Int64
    uid::Int64
    gid::Int64
    mode::UInt32
end

"""
    ArchiveHandle

A handle on a static archive (an `ar` archive, e.g. `libfoo.a` or `foo.lib`).
Iterate over it to get the [`ArchiveMember`](@ref)s, then `readmeta(ah, member)`
to open one as an object file, or `read(ah, member)` to get its contents.

The `ar` format comes in several kinds (see [`archive_kind()`](@ref)), which
differ in how they name members and index symbols.  GNU thin archives, whose
members are stored outside of the archive, are supported too (see `isthin()`).

Archives are not opened by `readmeta(io)`, as they are a collection of object
files, not one.  Use `readmeta(io, ArchiveHandle)` instead.
"""
struct ArchiveHandle{T<:IO}
    # Backing IO and start point within the IOStream of this archive
    io::T
    start::Int64

    # The kind of archive, see `archive_kind()`
    kind::Symbol

    # Whether this is a GNU thin archive, whose members are stored outside of it
    thin::Bool

    # Members, in archive order, excluding symbol and name tables
    members::Vector{ArchiveMember}

    # The path of the file this was created with, if it exists
    path::String
end

# A member as framed by its header within the archive, before its name (which
# may refer to data elsewhere, see `member_name()`) is resolved
struct RawMember
    header_offset::Int64
    header::ArchiveMemberHeader
    data_offset::Int64
    size::Int64
end

# The member's name field, without its padding
name_field(raw::RawMember) = field_string(raw.header.name)

function malformed(raw::RawMember, msg)
    throw(ArgumentError("Malformed archive member at offset $(raw.header_offset): $(msg)"))
end

function read_raw_members(io::IO, start::Integer, thin::Bool)
    raw = RawMember[]
    while !eof(io)
        header_offset = position(io) - start
        header = unpack(io, ArchiveMemberHeader)
        if collect(header.fmag) != AR_FMAG
            throw(ArgumentError("Malformed archive member header at offset $(header_offset)"))
        end
        data_offset = position(io) - start
        size = parse_field(header.size)
        push!(raw, RawMember(header_offset, header, data_offset, size))

        # Skip to the next header, which is aligned to an even offset.  A thin
        # archive (which is always of the GNU kind) only stores the members that
        # index it within itself.
        if !thin || is_index_member(:gnu, field_string(header.name))
            next_offset = data_offset + size
            seek(io, start + next_offset + isodd(next_offset))
        end
    end
    return raw
end

is_gnu(kind::Symbol) = kind in (:gnu, :gnu64)
is_bsd(kind::Symbol) = kind in (:bsd, :bsd64)

# Whether `name` is that of a member which indexes an archive of the given kind
# (a symbol or long name table), rather than being a part of it
function is_index_member(kind::Symbol, name::AbstractString)
    if is_bsd(kind)
        return name in BSD_SYMTAB || name in BSD_SYMTAB64
    end
    return name in (GNU_SYMTAB, GNU_SYMTAB64, GNU_NAMETAB, COFF_EC_SYMTAB)
end

# Look up a name stored at `offset` in the long name table.  GNU terminates names
# with "/\n", COFF with a NUL.
function lookup_long_name(raw::RawMember, kind::Symbol, table::Union{Nothing,Vector{UInt8}})
    field = name_field(raw)
    offset = tryparse(Int, field[2:end])
    if table === nothing
        malformed(raw, "long name $(repr(field)) without a long name table")
    elseif offset === nothing || !(0 <= offset < length(table))
        malformed(raw, "long name $(repr(field)) is outside of the long name table")
    end
    terminator = kind == :coff ? 0x00 : UInt8('\n')
    stop = findnext(==(terminator), table, offset + 1)
    if stop === nothing
        malformed(raw, "long name $(repr(field)) is not terminated")
    end
    name = String(table[offset+1:stop-1])
    if kind != :coff
        endswith(name, "/") || malformed(raw, "long name $(repr(name)) is not terminated by \"/\"")
        name = name[1:end-1]
    end
    return name
end

"""
    member_name(io, start, raw, kind, long_names)

Resolve the name of the member `raw` of an archive (starting at `start` within
`io`) of the given `kind`, returning it along with how many bytes at the start of
the member's data it takes up:

 - BSD stores names that are long (or contain spaces) at the start of the
   member's data, naming the member `#1/<length of name>`.
 - GNU and COFF refer to long names as `/<offset>` into the `long_names` table,
   and terminate short names with a "/" (to allow for trailing spaces).  The
   members that index the archive have reserved names (e.g. `/` and `//`),
   which are returned as-is.
"""
function member_name(io::IO, start::Integer, raw::RawMember, kind::Symbol, long_names)
    field = name_field(raw)
    if is_bsd(kind)
        startswith(field, BSD_LONG_NAME_PREFIX) || return field, 0
        name_size = tryparse(Int, field[length(BSD_LONG_NAME_PREFIX)+1:end])
        if name_size === nothing || !(0 <= name_size <= raw.size)
            malformed(raw, "invalid BSD long name $(repr(field))")
        end
        seek(io, start + raw.data_offset)
        return rstrip(String(read(io, name_size)), '\0'), name_size
    end

    if is_index_member(kind, field)
        return field, 0
    elseif startswith(field, "/")
        return lookup_long_name(raw, kind, long_names), 0
    elseif endswith(field, "/")
        return field[1:end-1], 0
    end
    malformed(raw, "member name $(repr(field)) is not terminated by \"/\"")
end

# Determine the kind of archive from its first member(s), along with how many of
# them are symbol tables
function detect_kind(io::IO, start::Integer, raw::Vector{RawMember})
    # An empty archive is the same in every kind
    isempty(raw) && return :gnu, 0

    field = name_field(raw[1])
    if field == GNU_SYMTAB
        # COFF archives start with two linker members, both named like a GNU symbol table
        return length(raw) > 1 && name_field(raw[2]) == GNU_SYMTAB ? (:coff, 2) : (:gnu, 1)
    elseif field == GNU_SYMTAB64
        return :gnu64, 1
    elseif startswith(field, "/") || endswith(field, "/")
        # Without a symbol table, a GNU archive starts with its name table ("//")
        # or a member, whose names are always terminated (or referred to) by a "/".
        return :gnu, 0
    end

    # Otherwise this is a BSD archive, possibly starting with its symbol table
    name = first(member_name(io, start, raw[1], :bsd, nothing))
    return name in BSD_SYMTAB64 ? (:bsd64, 1) : (:bsd, Int(name in BSD_SYMTAB))
end

function readmeta(io::IO, ::Type{ArchiveHandle})
    start = position(io)
    magic = read(io, length(AR_MAGIC))
    thin = magic == AR_THIN_MAGIC
    if magic != AR_MAGIC && !thin
        throw(MagicMismatch("Magic Number $(repr(String(magic))) does not match expected archive magic number $(repr(String(AR_MAGIC)))"))
    end

    raw = read_raw_members(io, start, thin)
    kind, num_symtabs = detect_kind(io, start, raw)
    if thin && !is_gnu(kind)
        throw(ArgumentError("Malformed archive: thin archives must be of the GNU kind, not $(kind)"))
    end

    # Skip over the members that index the archive, which come first: the symbol
    # table(s), then (for GNU and COFF) an optional long name table, then (for
    # COFF) an optional ARM64EC symbol table.
    idx = 1 + num_symtabs
    long_names = nothing
    if !is_bsd(kind) && idx <= length(raw) && name_field(raw[idx]) == GNU_NAMETAB
        seek(io, start + raw[idx].data_offset)
        long_names = read(io, raw[idx].size)
        idx += 1
    end
    if kind == :coff && idx <= length(raw) && name_field(raw[idx]) == COFF_EC_SYMTAB
        idx += 1
    end

    members = ArchiveMember[]
    for r in raw[idx:end]
        name, name_size = member_name(io, start, r, kind, long_names)
        if is_index_member(kind, name)
            malformed(r, "unexpected $(repr(name)) member in a $(kind) archive")
        end
        push!(members, ArchiveMember(
            name,
            thin ? nothing : r.data_offset + name_size,
            r.size - name_size,
            parse_field(r.header.mtime),
            parse_field(r.header.uid),
            parse_field(r.header.gid),
            UInt32(parse_field(r.header.mode, 8)),
        ))
    end

    return ArchiveHandle(io, Int64(start), kind, thin, members, path(io))
end

"""
    archive_kind(ah::ArchiveHandle)

Return the kind of the archive `ah`, which determines how it names its members
and indexes their symbols:

 - `:gnu`: System V / GNU archives, with a `/` symbol table, and a `//` table of
   long names (referred to as `/<offset>`)
 - `:gnu64`: GNU archives with a 64-bit (`/SYM64/`) symbol table
 - `:bsd`: BSD (incl. Darwin) archives, with a `__.SYMDEF` symbol table, and long
   names stored before the member's data (named `#1/<length>`)
 - `:bsd64`: BSD archives with a 64-bit (`__.SYMDEF_64`) symbol table
 - `:coff`: COFF (e.g. MSVC) archives, which start with two `/` linker members,
   and have GNU-like names (but NUL-terminated long names)

Archives without a symbol table are told apart by their member names, as only
GNU (and COFF) names are terminated by a `/`.
"""
archive_kind(ah::ArchiveHandle) = ah.kind

"""
    isthin(ah::ArchiveHandle)

Returns `true` if `ah` is a GNU thin archive, whose members are not stored within
the archive, but referred to by their path relative to it.
"""
isthin(ah::ArchiveHandle) = ah.thin

path(ah::ArchiveHandle) = ah.path

# An archive is an indexable collection of its members
keys(ah::ArchiveHandle) = keys(ah.members)
iterate(ah::ArchiveHandle, idx=1) = iterate(ah.members, idx)
length(ah::ArchiveHandle) = length(ah.members)
firstindex(ah::ArchiveHandle) = firstindex(ah.members)
lastindex(ah::ArchiveHandle) = lastindex(ah.members)
eltype(::Type{<:ArchiveHandle}) = ArchiveMember
getindex(ah::ArchiveHandle, idx) = ah.members[idx]

# Seek to the data of `member`, which must be stored within the archive
function seek_member(ah::ArchiveHandle, member::ArchiveMember)
    if member.offset === nothing
        throw(ArgumentError("Member $(member.name) of thin archive $(ah.path) is stored outside of the archive"))
    end
    seek(ah.io, ah.start + member.offset)
end

"""
    read(ah::ArchiveHandle, member::ArchiveMember)

Read the contents of `member` out of the archive `ah`.
"""
function read(ah::ArchiveHandle, member::ArchiveMember)
    seek_member(ah, member)
    return read(ah.io, member.size)
end

"""
    readmeta(ah::ArchiveHandle, member::ArchiveMember)

Read the object file stored as `member` of the archive `ah`, as `readmeta(io)`
would.  The resulting handles share their IO with `ah`.
"""
function readmeta(ah::ArchiveHandle, member::ArchiveMember)
    seek_member(ah, member)
    return readmeta(ah.io)
end

function show(io::IO, ah::ArchiveHandle)
    print(io, "Archive Handle ($(archive_kind(ah)), $(length(ah)) members$(isthin(ah) ? ", thin" : ""))")
end

end # module Archive
