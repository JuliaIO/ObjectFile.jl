export ELFVersionData, ELFVersionNeededData, ELFHash

# Special ELF version data structures
@io struct ELFVerDef{H <: ELFHandle}
    vd_version::UInt16
    vd_flags::UInt16
    vd_ndx::UInt16
    vd_cnt::UInt16
    vd_hash::UInt32
    vd_aux::UInt32
    vd_next::UInt32
end

@io struct ELFVerdAux{H <: ELFHandle}
    vda_name::UInt32
    vda_next::UInt32
end

@io struct ELFVerNeed{H <: ELFHandle}
    vn_version::UInt16
    vn_cnt::UInt16
    vn_file::UInt32
    vn_aux::UInt32
    vn_next::UInt32
end

@io struct ELFVernAux{H <: ELFHandle}
    vna_hash::UInt32
    vna_flags::UInt16
    vna_other::UInt16
    vna_name::UInt32
    vna_next::UInt32
end

struct ELFVersionEntry{H <: ELFHandle}
    ver_def::ELFVerDef{H}
    names::Vector{String}
end

struct ELFVersionNeededEntry{H <: ELFHandle}
    ver_need::ELFVerNeed{H}
    auxes::Vector{ELFVernAux}
    names::Vector{String}
end

"""
    read_version_struct(oh, s, offset, T)

Read a `T` from `offset` bytes into the version section `s`, throwing an error
if it would extend past the end of the section.
"""
function read_version_struct(oh::ELFHandle, s::ELFSectionRef, offset::Integer, ::Type{T}) where {T}
    if offset + packed_sizeof(T) > section_size(s)
        error("Malformed $(section_name(s)) section: $(nameof(T)) at offset $(offset) " *
              "runs past the end of the section ($(section_size(s)) bytes)")
    end
    seek(oh, section_offset(s) + offset)
    return unpack(oh, T)
end

"""
    version_name(strtab, name_offset)

Look up a version or library name in `.dynstr`, throwing an error if
`name_offset` lies outside of it.
"""
function version_name(strtab::ELFStrTab, name_offset::Integer)
    dynstr = strtab.section_ref
    if name_offset >= section_size(dynstr)
        error("Malformed version section: name offset $(name_offset) lies outside " *
              "of $(section_name(dynstr)) ($(section_size(dynstr)) bytes)")
    end
    return strtab_lookup(strtab, name_offset)
end

"""
    version_sections(oh, name)

Return the version section `name` and the `.dynstr` section its names point
into, or `nothing` if either is missing or has no contents in the file.
"""
function version_sections(oh::ELFHandle, name::AbstractString)
    s = findfirst(Sections(oh), name)
    dynstr = findfirst(Sections(oh), ".dynstr")
    (isnothing(s) || isnothing(dynstr)) && return nothing
    # Split-debuginfo files keep these section headers, but not their contents
    (section_has_contents(s) && section_has_contents(dynstr)) || return nothing
    section_size(s) == 0 && return nothing
    return s, StrTab(dynstr)
end

"""
Collect all version definitions from .gnu.version_d.  This section contains a
sequence of verdef structs `vd`, each of which owns exactly `vd.vd_cnt` verdaux
structs which we convert to names.  The first name is generally the only
important one to the given `vd`; it is the version being defined, and
corresponds to `vd.vd_hash`.  If present, a second verdaux usually notes the
parent version (e.g. `names = ["GLIBCXX_3.4.7", "GLIBCXX_3.4.6"]`)

Returns an empty list if the section is missing, empty, or `SHT_NOBITS`, and
throws an error if an entry or name points outside of its section.
"""
function ELFVersionData(oh::H) where {H <: ELFHandle}
    version_defs = ELFVersionEntry[]
    secs = version_sections(oh, ".gnu.version_d")
    isnothing(secs) && return version_defs
    s, strtab = secs

    # Every offset is relative to the start of the section.  `vd_next` and
    # `vda_next` are unsigned, so a nonzero step always moves forward, and the
    # bounds check in `read_version_struct()` ends the walk.
    vd_offset = 0
    while true
        vd = read_version_struct(oh, s, vd_offset, ELFVerDef{H})

        # Find aux names and resolve immediately to strings
        names = String[]
        aux_offset = vd_offset + vd.vd_aux
        for aux_idx in 1:vd.vd_cnt
            aux = read_version_struct(oh, s, aux_offset, ELFVerdAux{H})
            push!(names, version_name(strtab, aux.vda_name))
            aux.vda_next == 0 && break
            aux_offset += aux.vda_next
        end

        push!(version_defs, ELFVersionEntry(vd, names))

        vd.vd_next == 0 && break
        vd_offset += vd.vd_next
    end

    return version_defs
end

"""
Collect all version requirements from .gnu.version_r.  This section is
structurally similar to the version definition section, but the primary
"verneed" struct corresponds to one shared library, and the auxiliary struct
corresponds to a version.

Returns an empty list if the section is missing, empty, or `SHT_NOBITS`, and
throws an error if an entry or name points outside of its section.
"""
function ELFVersionNeededData(oh::H) where {H <: ELFHandle}
    verneeds = ELFVersionNeededEntry[]
    secs = version_sections(oh, ".gnu.version_r")
    isnothing(secs) && return verneeds
    s, strtab = secs

    # Offsets are relative to the start of the section, as in `ELFVersionData()`
    vn_offset = 0
    while true
        vn = read_version_struct(oh, s, vn_offset, ELFVerNeed{H})
        auxes = ELFVernAux[]
        names = String[]
        aux_offset = vn_offset + vn.vn_aux
        for aux_idx in 1:vn.vn_cnt
            aux = read_version_struct(oh, s, aux_offset, ELFVernAux{H})
            push!(auxes, aux)
            push!(names, version_name(strtab, aux.vna_name))
            aux.vna_next == 0 && break
            aux_offset += aux.vna_next
        end
        push!(verneeds, ELFVersionNeededEntry(vn, auxes, names))

        vn.vn_next == 0 && break
        vn_offset += vn.vn_next
    end

    return verneeds
end

"""
See https://en.wikipedia.org/wiki/PJW_hash_function

Hash function used to create vd_hash from vda_name, or vna_hash from vna_name.
Stops at the first null byte.
"""
function ELFHash(v::Vector{UInt8})
    h = UInt32(0)
    for b in v
        (b == 0) && break;
        h = (h << 4) + b
        hi = h & 0xf0000000
        if (hi != 0)
            h ⊻= (hi >> 24)
        end
        h &= ~hi
    end
    return h
end
