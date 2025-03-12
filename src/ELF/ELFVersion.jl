export ELFVersionData

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

function ELFVersionData(oh::H) where {H <: ELFHandle}
    s = findfirst(Sections(oh), ".gnu.version_d")
    strtab = StrTab(findfirst(Sections(oh), ".dynstr"))

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
Hash function used to create vd_hash from vda_name, or vna_hash from vna_name
"""
function ELFHash(v::Vector{UInt8})
    h = UInt32(0)
    for b in v
        h = (h << 4) + b
        hi = h & 0xf0000000
        if (hi != 0)
            h ⊻= (hi >> 24)
        end
        h &= ~hi
    end
    return h
end
