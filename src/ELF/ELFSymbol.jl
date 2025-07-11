export ELFSymbols, ELFSymtabEntry, ELFSymtabEntry64, ELFSymtabEntry32, ELFSymbolRef

"""
    ELFSymbols

ELF symbol table, contains the list of symbols defined within the object file.
"""
struct ELFSymbols{H<:ELFHandle} <: Symbols{H}
    section_ref::SectionRef{H}
end

function Symbols(section::SectionRef{H}) where {H <: ELFHandle}
    return ELFSymbols(section)
end

"""
    Symbols(oh::ELFHandle)

Return the `ELFSymbols` object that is contained within the first `.dynsym` or
`.symtab` section within the ELF object.
"""
function Symbols(oh::H) where {H <: ELFHandle}
    sections = Sections(oh)
    # First, try to load `.symtab`.  If we can't load that guy, we'll fall back
    # to `.dynsym` which has less information, but is more likely to exist.
    dyn_sections = findall(sections, ".symtab")
    if !isempty(dyn_sections)
        return ELFSymbols(first(dyn_sections))
    end

    dyn_sections = findall(sections, ".dynsym")
    if !isempty(dyn_sections)
        return ELFSymbols(first(dyn_sections))
    end
    error("Could not find a .dynsym or .symtab section in object file")
end

"""
    Section(syms::ELFSymbols)

Return the `Section` that contains this ELF symbol table.
"""
Section(syms::ELFSymbols) = syms.section_ref
handle(syms::ELFSymbols) = handle(Section(syms))
symtab_entry_type(syms::ELFSymbols) = symtab_entry_type(handle(syms))

function lastindex(syms::ELFSymbols{H}) where {H <: ELFHandle}
    sect_size = section_size(Section(syms))
    sym_size = sizeof(symtab_entry_type(syms))
    return div(sect_size, sym_size)
end


# Add an StrTab() override to be able to load the symbol string table
"""
    StrTab(syms::ELFSymbols)

Given an ELF `Symbols` container, construct an `ELFStrTab` that refers to the
associated symbol string table.
"""
function StrTab(syms::ELFSymbols{H}) where {H <: ELFHandle}
    # The `sh_link` field in a symbol section always points to the symbol table
    section_idx = deref(Section(syms)).sh_link+1
    strtab_section = Sections(handle(syms))[section_idx]
    return ELFStrTab{H}(strtab_section)
end



"""
    ELFSymtabEntry

ELF Symtab Entry type, contains the data relevant to a symbol defined within
this ELF file, garnered from the symbol table (symtab)
"""
abstract type ELFSymtabEntry{H <: ELFHandle} <: SymtabEntry{H} end

@io struct ELFSymtabEntry32{H <: ELFHandle} <: ELFSymtabEntry{H}
    st_name::UInt32
    st_value::UInt32
    st_size::UInt32
    st_info::UInt8
    st_other::UInt8
    st_shndx::UInt16
end

@io struct ELFSymtabEntry64{H <: ELFHandle} <: ELFSymtabEntry{H}
    st_name::UInt32
    st_info::UInt8
    st_other::UInt8
    st_shndx::UInt16
    st_value::UInt64
    st_size::UInt64
end

function read(oh::ELFHandle, ::Type{ST}) where {ST <: ELFSymtabEntry}
    type_func = symtab_entry_type
    size_func = symtab_entry_size
    return read_struct(oh, type_func, size_func, "Symbol Entry")
end


# Define two helper functions that return ELF-specific symbol infos
st_bind(st_info::UInt8) = st_info >> 4
st_type(st_info::UInt8) = st_info & 0xf

# Define helper functions to detect symbols marked as "reserved"
function isreserved(sym::ELFSymtabEntry)
    return SHN_LORESERVE <= sym.st_shndx <= SHN_HIRESERVE
end

symbol_name(sym::ELFSymtabEntry) = string("strtab@", sym.st_name)
symbol_value(sym::ELFSymtabEntry) = sym.st_value
isundef(sym::ELFSymtabEntry) = (sym.st_shndx == SHN_UNDEF)
isglobal(sym::ELFSymtabEntry) = (st_bind(sym.st_info) & STB_GLOBAL) != 0
islocal(sym::ELFSymtabEntry) = !isglobal(sym)
isweak(sym::ELFSymtabEntry) = (st_bind(sym.st_info) & STB_WEAK) != 0


"""
    ELFSymbolRef

Contains a reference to an `ELFSymtabEntry`, as well as an `ELFSymbols`, etc...
"""
struct ELFSymbolRef{H<:ELFHandle} <: SymbolRef{H}
    syms::ELFSymbols{H}
    entry::ELFSymtabEntry{H}
    idx::UInt32
end
function SymbolRef(syms::ELFSymbols, entry::ELFSymtabEntry, idx)
    return ELFSymbolRef(syms, entry, UInt32(idx))
end

deref(sym::ELFSymbolRef) = sym.entry
Symbols(sym::ELFSymbolRef) = sym.syms

@derefmethod isreserved(sym::ELFSymbolRef)
symbol_number(sym::ELFSymbolRef) = sym.idx
function symbol_name(sym::ELFSymbolRef)
    # We look up the symbol name in the linked string table for this particular section
    strtab = StrTab(Symbols(sym))
    return strtab_lookup(strtab, deref(sym).st_name)
end
# Helper function to get the section a symbol refers to
symbol_section(sym::ELFSymbolRef) = Sections(handle(sym))[deref(sym).st_shndx + 1]

function symbol_value(sym::ELFSymbolRef)
    # First, grab the actual `st_value` entry from the SymtabEntry
    value = symbol_value(deref(sym))

    # If the given symbol is defined, and is not reserved
    if !isundef(sym) && !isreserved(sym)
        # Grab the address of the section this symbol refers to
        sh_addr = section_address(symbol_section(sym))

        # What to do next depends on the object kind. Shared libraries and
        # executable's st_value's are virtual addresses
        e_type = header(handle(sym)).e_type

        # If this is a plain relocatable file (`.o` file) just increment by
        # section address
        if sh_addr != 0 && e_type == ET_REL
            value += sh_addr
        end

        # If this is an executable or dynamic library
        if e_type in (ET_EXEC, ET_DYN)
            # Subtract off the virtual address of the first PT_LOAD segment
            P = [s for s in Segments(handle(sym)) if segment_type(s) == PT_LOAD]
            if !isempty(P)
                value -= segment_virtual_address(first(P))
            end
        end
    end

    # Return our ill-gotten goods
    return value
end

function symbol_offset(sym::ELFSymbolRef)
    addr = symbol_value(sym)
    sect = symbol_section(sym)
    virtual_offset =  section_address(sect) - section_offset(sect)
    return addr - virtual_offset
end
