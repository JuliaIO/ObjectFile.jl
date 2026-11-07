# Export Mach-O specific stuff that is useful
export MachOLoadCmd, MachOLoadCmdHeader, MachOLoadCmds, MachOLoadCmdRef


"""
    MachOLoadCmdHeader

All MachO Load Commands have a common header, containing information about what
kind of Load Command it is, and how large the load command is.
"""
@io struct MachOLoadCmdHeader{H <: MachOHandle}
    cmd::UInt32
    cmdsize::UInt32
end


"""
    MachOLoadCmd

Abstraction over all Load Commands that can exist within a Mach-O object file,
containing subclasses such as `MachOSegmentCmd` or `MachODySymtabCmd`.
The list of available API operations is given below, with methods that
subclasses must implement marked in emphasis:

### Creation
  - MachOLoadCmd()
"""
abstract type MachOLoadCmd{H <: MachOHandle} end


"""
    MachOLoadCmd(oh::MachOHandle, CT::Type, header)

Construct a `MachOLoadCmd` from the given `MachOHandle`, constructing an object
of type `CT` (which can be calculated via `load_cmd_type(header)`, but is
explicitly passed to `MachOLoadCmd()` for dispatch purposes).
"""
function MachOLoadCmd(oh::MachOHandle, CT::Type, header)
    # In general, just unpack the type
    return unpack(oh, CT)
end



"""
    MachOLoadCmds

Allows iteration over the LoadCmds within a Mach-O file.

### Creation
  - MachOLoadCmds()

### Iteration
  - getindex()
  - lastindex()
  - iterate()
  - keys()
  - length()
  - eltype()

### Access
  - find

### Convenience constructors
  - Segments()
"""
struct MachOLoadCmds{H <: MachOHandle}
    handle::H
    headers::Vector{MachOLoadCmdHeader{H}}
    cmds::Vector{MachOLoadCmd{H}}
    positions::Vector{UInt32}
end

"""
    MachOLoadCmdRef

Datatype containing a Mach-O Load Command, its header, and a reference back to
the `MachOLoadCmds` object it was garnered from
"""
struct MachOLoadCmdRef{H <: MachOHandle, C <: MachOLoadCmd{H}}
    lcs::MachOLoadCmds{H}
    header::MachOLoadCmdHeader{H}
    cmd::C
    position::UInt32
end

MachOLoadCmds(lcr::MachOLoadCmdRef) = lcr.lcs
handle(lcr::MachOLoadCmdRef) = handle(MachOLoadCmds(lcr))
header(lcr::MachOLoadCmdRef) = lcr.header
deref(lcr::MachOLoadCmdRef) = lcr.cmd
position(lcr::MachOLoadCmdRef) = lcr.position
seek(lcr::MachOLoadCmdRef) = seek(handle(lcr), position(lcr))
type_str(cmd::MachOLoadCmdRef) = load_cmd_type_string(header(cmd))


include("LoadCmds/UnknownCmd.jl")
include("LoadCmds/DylibCmds.jl")
include("LoadCmds/SegmentCmds.jl")
include("LoadCmds/SymtabCmds.jl")
include("LoadCmds/VersionCmds.jl")

function show(io::IO, cmd::MachOLoadCmd)
    print(io, "MachOLoadCmd")
end

function show(io::IO, cmd::MachOLoadCmdRef)
    print(io, "MachOLoadCmd $(type_str(cmd))")
end

"""
    MachOLoadCmds(oh::MachOHandle)

Load the set of Mach-O Load Commands from the given object handle.
"""
function MachOLoadCmds(oh::H) where {H <: MachOHandle}
    # These are the cmds we will read in
    headers = MachOLoadCmdHeader{H}[]
    cmds = MachOLoadCmd{H}[]
    positions = UInt32[]

    # Begin by seeking to the header offset
    seek(oh, sizeof(header(oh)))

    for idx in 1:header(oh).ncmds
        # Unpack each load command.  First, read in the header:
        cmd_header = unpack(oh, MachOLoadCmdHeader{H})

        # Examine its type, and proceed to unpack the rest of the command
        cmd_pos = position(oh)
        next_cmd_pos = cmd_pos + load_cmd_size(cmd_header)
        cmd = MachOLoadCmd(oh, load_cmd_type(cmd_header), cmd_header)

        # We do this because commands are variable-size and sometimes we don't
        # actually read the whole thing.
        seek(oh, next_cmd_pos)

        push!(headers, cmd_header)
        push!(cmds, cmd)
        push!(positions, cmd_pos)
    end

    return MachOLoadCmds(oh, headers, cmds, positions)
end

handle(lcs::MachOLoadCmds) = lcs.handle
header(lcs::MachOLoadCmds) = header(handle(lcs))

# Iteration
keys(lcs::MachOLoadCmds) = 1:length(lcs)
iterate(lcs::MachOLoadCmds, idx=1) = idx > length(lcs) ? nothing : (lcs.cmds[idx], idx+1)
lastindex(lcs::MachOLoadCmds) = lastindex(lcs.cmds)
length(lcs::MachOLoadCmds) = length(lcs.cmds)
eltype(::Type{S}) where {S <: MachOLoadCmds} = MachOLoadCmdRef
function getindex(l::MachOLoadCmds, idx)
    return MachOLoadCmdRef(l, l.headers[idx], l.cmds[idx], l.positions[idx])
end

# Searching
"""
    findall(lcs::MachOLoadCmds, lc_types::Vector{Type})

Given a list of `Type`s, filter out all load commands within `lcs` that are not
of that type.  This method returns a `Vector` of `MachOLoadCmdRef` objects,
containing only load commands that are of the requested types.  For example, to
find all segments within a file:

    findall(MachOLoadCmds(oh), [MachOSegmentCmd])
"""
function findall(lcs::MachOLoadCmds, lc_types::Vector{T}) where {T <: Type}
    indices = Integer[]
    for idx in 1:length(lcs.cmds)
        if any(typeof(lcs.cmds[idx]) <: lct for lct in lc_types)
            push!(indices, idx)
        end
    end

    # Return a new MachOLoadCmds object, that has those headers defined within it
    return [lcs[idx] for idx in indices]
end
findall(lcs::MachOLoadCmds, lc_type::T) where {T <: Type} = findall(lcs, [lc_type])


function load_cmd_type(header::MachOLoadCmdHeader{H}) where {H <: MachOHandle}
    type_mapping = Dict(
        LC_SEGMENT => MachOSegment32Cmd{H},
        LC_SEGMENT_64 => MachOSegment64Cmd{H},
        LC_LOAD_DYLIB => MachOLoadDylibCmd{H},
        LC_ID_DYLIB => MachOIdDylibCmd{H},
        LC_RPATH => MachORPathCmd{H},
        LC_SYMTAB => MachOSymtabCmd{H},
        LC_VERSION_MIN_MACOSX => MachOVersionMinCmd{H},
        LC_VERSION_MIN_IPHONEOS => MachOVersionMinCmd{H},
        LC_VERSION_MIN_TVOS => MachOVersionMinCmd{H},
        LC_VERSION_MIN_WATCHOS => MachOVersionMinCmd{H},
        LC_BUILD_VERSION => MachOBuildVersionCmd{H},
    )

    # We drop LC_REQ_DYLD from the flags because we don't care
    return get(type_mapping, header.cmd & ~LC_REQ_DYLD, MachOUnknownCmd{H})
end

function load_cmd_type_string(header::MachOLoadCmdHeader{H}) where {H <: MachOHandle}
    global LCTYPES

    if haskey(LCTYPES, header.cmd)
        return LCTYPES[header.cmd]
    end
    return string("Unknown Type (0x", string(header.cmd, base=16), ")")
end

"""
    load_cmd_size(header::MachOLoadCmdHeader)

Return the size, in bytes, of the referred `MachOLoadCmd`, not counting the
space for the header itself.
"""
function load_cmd_size(header::MachOLoadCmdHeader{H}) where {H <: MachOHandle}
    return header.cmdsize - packed_sizeof(MachOLoadCmdHeader{H})
end

function show(io::IO, lcs::MachOLoadCmds)
    print(io, "MachO Load Commands")
    for lc in lcs
        print(io, "\n  ")
        show(io, lc)
    end
end

"""
    unpack_lcstr(oh::MachOHandle, offset, max_size)

Given a Load Command STRing located `offset` bytes ahead in the current file,
and ending no more than `max_size` bytes ahead, read it in and return it as a
Julia-native `String`.  If the given offset is bad in some way (it is negative,
or begins beyond the end of `max_size`) an error string is returned.
"""
function unpack_lcstr(oh::H, offset, max_size) where {H <: MachOHandle}
    # Perform sanity checking on offset; if it is too small or too large,
    # don't try to read the lc_str, just assign it "<lc_str offset corrupt>"
    if offset >= 0 && offset < max_size
        # Skip ahead to the given offset
        skip(oh, offset)

        # Read in the cstring
        return unsafe_string(oh, max_size - offset)
    else
        # If we are outside the bounds, (either the string begins in the middle
        # of the rest of the struct, or it begins outside of this load command)
        # do not attempt to automatically read it
        return "<lc_str offset corrupt>"
    end
end
