export MachOSymtabEntry, MachOSymbolRef, MachOSymbols

"""
    MachOSymtabEntry

MachO Symbol Table entry type, internally represented as an `nlist` type.
"""
abstract type MachOSymtabEntry{H <: MachOHandle} <: SymtabEntry{H} end
@io struct nlist{H <: MachOHandle} <: MachOSymtabEntry{H}
    n_strx::UInt32
    n_type::UInt8
    n_sect::UInt8
    n_desc::UInt16
    n_value::UInt32
end

@io struct nlist_64{H <: MachOHandle} <: MachOSymtabEntry{H}
    n_strx::UInt32
    n_type::UInt8
    n_sect::UInt8
    n_desc::UInt16
    n_value::UInt64
end

symbol_name(sym::MachOSymtabEntry) = string("strtab@", sym.n_strx)
symbol_value(sym::MachOSymtabEntry) = sym.n_value
symbol_type(sym::MachOSymtabEntry) = sym.n_type
symbol_description(sym::MachOSymtabEntry) = sym.n_desc

function isglobal(sym::MachOSymtabEntry)
    return (symbol_type(sym) & N_EXT) != 0
end
function islocal(sym::MachOSymtabEntry)
    return !isglobal(sym) && (symbol_type(sym) == N_UNDF)
end
function isweak(sym::MachOSymtabEntry)
    return (symbol_description(sym) & (N_WEAK_REF | N_WEAK_DEF)) != 0
end
function isundef(sym::MachOSymtabEntry)
    return (symbol_type(sym) == N_UNDF) ||
           (isglobal(sym) && sym.n_sect == NO_SECT)
end



"""
    MachOSymbols

MachO container type for `SymtabEntry` objects.
"""
struct MachOSymbols{H <: MachOHandle} <: Symbols{H}
    cmd::MachOLoadCmdRef{H,MachOSymtabCmd{H}}
end

function MachOSymbols(oh::MachOHandle)
    cmds = findall(MachOLoadCmds(oh), [MachOSymtabCmd])
    if isempty(cmds)
        error("Mach-O file does not contain Symtab load commands")
    end
    return MachOSymbols(first(cmds))
end

Symbols(oh::MachOHandle) = MachOSymbols(oh::MachOHandle)
function Symbols(cmd::MachOLoadCmdRef{H,MachOSymtabCmd{H}}) where {H <: MachOHandle}
    return MachOSymbols(cmd)
end

handle(syms::MachOSymbols) = handle(syms.cmd)
lastindex(syms::MachOSymbols) = symtab_num_symbols(syms.cmd)

symtab_entry_offset(syms::MachOSymbols) = symtab_symbols_offset(syms.cmd)
symtab_entry_size(syms::MachOSymbols) = sizeof(symtab_entry_type(syms))
function symtab_entry_type(syms::MachOSymbols{H}) where {H <: MachOHandle}
    if is64bit(handle(syms))
        return nlist_64{H}
    else
        return nlist{H}
    end
end

function getindex(syms::MachOSymbols, idx)
    # Punt off to `getindex_ref`
    return getindex_ref(
        syms,
        symtab_entry_offset(syms),
        symtab_entry_size(syms),
        symtab_entry_type(syms),
        SymbolRef,
        idx
    )
end


# Add an StrTab() override to be able to load the symbol string table
"""
    StrTab(syms::MachOSymbols)

Given a MachO `Symbols` container, construct a `MachOStrTab` that refers to the
associated symbol string table.
"""
StrTab(syms::MachOSymbols) = StrTab(syms.cmd)


struct MachOSymbolRef{H <: MachOHandle} <: SymbolRef{H}
    syms::MachOSymbols{H}
    entry::MachOSymtabEntry{H}
    idx::UInt32
end

function SymbolRef(syms::MachOSymbols, entry::MachOSymtabEntry, idx)
    return MachOSymbolRef(syms, entry, UInt32(idx))
end

deref(sym::MachOSymbolRef) = sym.entry
Symbols(sym::MachOSymbolRef) = sym.syms
symbol_number(sym::MachOSymbolRef) = sym.idx

function symbol_section(sym::MachOSymbolRef)
    # MachO uses 0 to indicate no section, so we use NO_SECT
    if deref(sym).n_sect == 0
        return NO_SECT
    end
    return Sections(handle(sym))[deref(sym).n_sect]
end

function symbol_name(sym::MachOSymbolRef)
    return strtab_lookup(StrTab(Symbols(sym)), sym.entry.n_strx)
end

function symbol_offset(sym::MachOSymbolRef)
    addr = symbol_value(sym)
    sect = symbol_section(sym)
    virtual_offset =  section_address(sect) - section_offset(sect)
    return addr - virtual_offset
end

