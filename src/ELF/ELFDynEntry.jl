# Export datatypes
export ELFDynEntry, ELFDynEntry32, ELFDynEntry64, ELFDynEntryRef, ELFDynEntries

# Export methods
export dyn_entry_type, dyn_entry_is_string, dyn_entry_type_string

import Base: show

"""
    ELFDynEntry

ELF Dynamic table entry type.  This is comprised by a `d_tag` member and a
`d_val` member; the `d_tag` tells what kind of command this is to the dynamic
linker (e.g. `DT_NEEDED` denotes a shared library that must be loaded for this
ELF object to link properly), whereas `d_val` is a pointer to another data
structure that contains more information.  (E.g. for a `DT_NEEDED` entry,
`d_val` would represent an offset within the dynamic string table)
"""
abstract type ELFDynEntry{H <: ELFHandle} end

@io struct ELFDynEntry32{H <: ELFHandle} <: ELFDynEntry{H}
    d_tag::UInt32
    # We drop the `d_un` union, and use only `d_val`, omitting `d_ptr`.
    d_val::UInt32
end

@io struct ELFDynEntry64{H <: ELFHandle} <: ELFDynEntry{H}
    d_tag::UInt64
    # We drop the `d_un` union, and use only `d_val`, omitting `d_ptr`.
    d_val::UInt64
end

"""
    dyn_entry_type(d::ELFDynEntry)

Return the type of the given `ELFDynEntry`
"""
dyn_entry_type(d::ELFDynEntry) = d.d_tag

"""
    dyn_entry_is_string(d::ELFDynEntry)

Return `true` if the given `ELFDynEntry` represents an offset within the
dynamic string table, and therefore can be used in a `strtab_lookup()`
"""
function dyn_entry_is_string(d::ELFDynEntry)
    string_types = [
        DT_NEEDED,
        DT_SONAME,
        DT_RPATH,
        DT_RUNPATH,
        DT_AUXILIARY,
        DT_FILTER,
        DT_CONFIG,
        DT_DEPAUDIT,
        DT_AUDIT
    ]
    return dyn_entry_type(d) in string_types
end

"""
    dyn_entry_type_string(d::ELFDynEntry)

Return the given `ELFDynEntry`'s type as a string.
"""
function dyn_entry_type_string(d::ELFDynEntry)
    global DYNAMIC_TYPE

    d_type = dyn_entry_type(d)
    if haskey(DYNAMIC_TYPE, d_type)
        return DYNAMIC_TYPE[d_type]
    end
    return string("Unknown DynEntry Type (0x", string(d_type, base=16), ")")
end

struct ELFDynEntryRef{H <: ELFHandle}
    section_ref::SectionRef{H}
    entry::ELFDynEntry{H}
end

Section(d::ELFDynEntryRef) = d.section_ref
handle(d::ELFDynEntryRef) = handle(Section(d))
deref(d::ELFDynEntryRef) = d.entry
@derefmethod dyn_entry_type(d::ELFDynEntryRef)
@derefmethod dyn_entry_is_string(d::ELFDynEntryRef)
strtab_lookup(d::ELFDynEntryRef) = strtab_lookup(StrTab(d), deref(d).d_val)


function show(io::IO, d::DT) where {DT <: ELFDynEntry}
    print(io, "ELFDynEntry", DT <: ELFDynEntry64 ? " (64 bit)" : "")
    print(io, " $(dyn_entry_type_string(d))")
end

function show(io::IO, d::ELFDynEntryRef)
    show(io, deref(d))
    if dyn_entry_is_string(d)
        print(io, ", \"$(strtab_lookup(d))\"")
    end
end

"""
    StrTab(d::ELFDynEntryRef)

Given an `ELFDynEntryRef`, construct an `ELFStrTab` that refers to the
associated dynamic string table.
"""
function StrTab(d::ELFDynEntryRef{H}) where {H <: ObjectHandle}
    # The `sh_link` field in a ".dynamic" section always points to the
    # dynamic string table (usually called ".dynstr")
    section_idx = deref(Section(d)).sh_link+1
    strtab_section = Sections(handle(d))[section_idx]
    return ELFStrTab{H}(strtab_section)
end


"""
    ELFDynEntries(oh::ELFHandle)

Read all `ELFDynEntry` objects from an ELF object, returning them as an array.
"""
function ELFDynEntries(oh::ELFHandle)
    dyn_section = findfirst(Sections(oh), ".dynamic")

    # Figure out what kind of DynEntry objects we're going to read in
    DT = dyn_entry_type(oh)

    # Split-debuginfo files keep the `.dynamic` header, but not its contents
    if !isnothing(dyn_section) && !section_has_contents(dyn_section)
        return ELFDynEntryRef{typeof(oh)}[]
    end

    # Seek to the proper spot, and read 'em in until we reach a DT_NULL
    seekstart(dyn_section)
    dts = [ELFDynEntryRef(dyn_section, unpack(oh, DT))]

    while dyn_entry_type(dts[end]) != DT_NULL
        push!(dts, ELFDynEntryRef(dyn_section, unpack(oh, DT)))
    end
    
    return dts
end

"""
    ELFDynEntries(oh::ELFHandle, kinds::Vector)

Read all `ELFDynEntry` objects from an ELF object, returning them as an array
if they are one of the `kinds` passed in, such as `DT_NEEDED`.
"""
function ELFDynEntries(oh::ELFHandle, kinds::Vector)
    return [d for d in ELFDynEntries(oh) if dyn_entry_type(d) in kinds]
end
