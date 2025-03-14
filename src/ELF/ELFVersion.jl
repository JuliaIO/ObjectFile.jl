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
    vn_file::UInt16
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
Collect all version definitions from .gnu.version_d.  This section contains a
sequence of verdef structs `vd`, each of which owns exactly `vd.vd_cnt` verdaux
structs which we convert to names.  The first name is generally the only
important one to the given `vd`; it is the version being defined, and
corresponds to `vd.vd_hash`.  If present, a second verdaux usually notes the
parent version (e.g. `names = ["GLIBCXX_3.4.7", "GLIBCXX_3.4.6"]`)
"""
function ELFVersionData(oh::H) where {H <: ELFHandle}
    s = findfirst(Sections(oh), ".gnu.version_d")
    strtab = StrTab(findfirst(Sections(oh), ".dynstr"))
    (isnothing(s) || isnothing(strtab)) && return ELFVersionEntry[]

    # Queue oh up to the beginning of this section
    seek(oh, section_offset(s))

    # Read out ALL OF THE version definitions
    version_defs = ELFVersionEntry[]
    while true
        vd_pos = position(oh)
        vd = unpack(oh, ELFVerDef{H})

        # Find aux names and resolve immediately to strings
        auxes = String[]
        aux_offset = 0
        for aux_idx in 1:vd.vd_cnt
            seek(oh, vd_pos + vd.vd_aux + aux_offset)
            aux = unpack(oh, ELFVerdAux{H})
            name = strtab_lookup(strtab, aux.vda_name)
            push!(auxes, name)  
            aux_offset += aux.vda_next
        end

        push!(version_defs, ELFVersionEntry(vd, auxes))

        if vd.vd_next == 0
            break
        end
        seek(oh, vd_pos + vd.vd_next)
    end
    
    return version_defs
end

"""
Collect all version requirements from .gnu.version_r.  This section is
structurally similar to the version definition section, but the primary
"verneed" struct corresponds to one shared library, and the auxiliary struct
corresponds to a version.
"""
function ELFVersionNeededData(oh::H) where {H <: ELFHandle}
    s = findfirst(Sections(oh), ".gnu.version_r")
    strtab = StrTab(findfirst(Sections(oh), ".dynstr"))
    (isnothing(s) || isnothing(strtab)) && return ELFVersionNeededEntry[]

    seek(oh, section_offset(s))
    verneeds = ELFVersionNeededEntry[]
    while true
        vn_pos = position(oh)
        vn = unpack(oh, ELFVerNeed{H})
        auxes = ELFVernAux[]
        names = String[]
        aux_offset = 0
        for aux_idx in 1:vn.vn_cnt
            seek(oh, vn_pos + vn.vn_aux + aux_offset)
            aux = unpack(oh, ELFVernAux{H})
            name = strtab_lookup(strtab, aux.vna_name)
            push!(auxes, aux)
            push!(names, name)
            aux_offset += aux.vna_next
        end
        push!(verneeds, ELFVersionNeededEntry(vn, auxes, names))

        if vn.vn_next == 0
            break
        end
        seek(oh, vn_pos + vn.vn_next)
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
