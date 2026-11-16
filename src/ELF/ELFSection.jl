export ELFSections, ELFSection, ELFSection32, ELFSection64, ELFSectionRef

# Export certain extensions to the base API
export section_type, section_has_contents

"""
    ELFSections

ELF Section header table type, containing information about the number of
sections within the ELF object, the location of the section headers, etc...
"""
struct ELFSections{H <: ELFHandle} <: Sections{ELFHandle}
    handle::H
end

Sections(oh::ELFHandle) = ELFSections(oh)

# Implement Sections API
handle(sections::ELFSections) = sections.handle
lastindex(sections::ELFSections) = header(handle(sections)).e_shnum


"""
    ELFSection

ELF Section type, containing information about a `Section` within the ELF
object, such as the `Section`'s name, its size, etc...
"""
abstract type ELFSection{H <: ELFHandle} <: Section{H} end
@io struct ELFSection32{H <: ELFHandle} <: ELFSection{H}
    sh_name::UInt32
    sh_type::UInt32
    sh_flags::UInt32
    sh_addr::UInt32
    sh_offset::UInt32
    sh_size::UInt32
    sh_link::UInt32
    sh_info::UInt32
    sh_addralign::UInt32
    sh_entsize::UInt32
end
@io struct ELFSection64{H <: ELFHandle} <: ELFSection{H}
    sh_name::UInt32
    sh_type::UInt32
    sh_flags::UInt64
    sh_addr::UInt64
    sh_offset::UInt64
    sh_size::UInt64
    sh_link::UInt32
    sh_info::UInt32
    sh_addralign::UInt64
    sh_entsize::UInt64
end

# Implement Section API
function read(oh::ELFHandle, ::Type{ST}) where {ST <: ELFSection}
    type_func = section_header_type
    size_func = section_header_size
    return read_struct(oh, type_func, size_func, "Section Header")
end

section_name(s::ELFSection) = string("strtab@", s.sh_name)
section_type(s::ELFSection) = s.sh_type
section_size(s::ELFSection) = s.sh_size
section_offset(s::ELFSection) = s.sh_offset
section_address(s::ELFSection) = s.sh_addr

"""
    section_has_contents(s::ELFSection)

Return `false` if the given section occupies no space in the file (its type is
`SHT_NOBITS`), so its `sh_offset`/`sh_size` don't describe any bytes that can be
read.  Besides `.bss`, this covers the loadable sections (`.dynamic`,
`.dynsym`, `.dynstr`, `.gnu.version_r`, ...) of a split-debuginfo file such as
one made by `objcopy --only-keep-debug`, which keeps their headers but not
their contents.
"""
section_has_contents(s::ELFSection) = section_type(s) != SHT_NOBITS



"""
    ELFSectionRef

ELF `SectionRef` type, containing an `ELFSection` and important metadata.
"""
struct ELFSectionRef{H<:ELFHandle} <: SectionRef{H}
    sections::ELFSections{H}
    section::ELFSection{H}
    idx::UInt32
end

function SectionRef(sections::ELFSections, s::ELFSection, idx)
    return ELFSectionRef(sections, s, UInt32(idx))
end
deref(s::ELFSectionRef) = s.section
sections(s::ELFSectionRef) = s.sections
handle(s::ELFSectionRef) = handle(sections(s))
section_number(s::ELFSectionRef) = s.idx
@derefmethod section_type(s::ELFSectionRef)
@derefmethod section_has_contents(s::ELFSectionRef)

function section_name(section::ELFSectionRef)
    # Actually do the strtab lookup to get the name of this guy
    strtab = StrTab(handle(section))
    return strtab_lookup(strtab, deref(section).sh_name)
end



"""
    section_type_string(s::ELFSection)

Return the given `ELFSection`'s section type as a string.
"""
function section_type_string(s::ELFSection)
    global SHT_TYPES

    sh_type = section_type(s)
    if haskey(SHT_TYPES, sh_type)
        return SHT_TYPES[sh_type]
    end
    return string("Unknown Section Type (0x", string(sh_type, base=16), ")")
end
@derefmethod section_type_string(s::ELFSectionRef)
