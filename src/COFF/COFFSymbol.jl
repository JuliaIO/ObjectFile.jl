export COFFSymbols, COFFSymtabEntry, COFFSymbolRef

"""
    COFFSymbols

COFF symbol table, contains the list of symbols defined within the object file.

Note that because COFF Symbols are followed by a variable number of auxiliary
records within the symbol table, we store the (1-based) symbol table index at
which each (non-auxiliary) symbol can be found.
"""
struct COFFSymbols{H<:COFFHandle} <: Symbols{H}
    handle::H
    symbol_indices::Vector{UInt32}
end

"""
    scan_symbol_indices(oh::COFFHandle)

Find the symbol table index of each Symbol within a COFFHandle, skipping over
auxiliary records as necessary.
"""
function scan_symbol_indices(oh::H) where {H <: COFFHandle}
    # num_syms represents the number of total records, but we're only
    # interested in the non-auxiliary symbols
    num_syms = num_symbols(header(oh))
    indices = UInt32[]

    idx = 1
    while idx <= num_syms
        # Load in the next symbol and store its index
        seek(oh, symtab_entry_offset(oh) + symtab_entry_size(oh)*(idx-1))
        sym = unpack(oh, symtab_entry_type(oh))
        push!(indices, idx)

        # Move our index forward by 1 (because we just read in a SymtabEntry)
        # and again as many times as needed to skip over the auxiliary records
        idx += 1 + sym.NumberOfAuxSymbols
    end

    return indices
end

function Symbols(oh::H) where {H <: COFFHandle}
    return COFFSymbols(oh, scan_symbol_indices(oh))
end

handle(syms::COFFSymbols) = syms.handle
lastindex(syms::COFFSymbols) = length(syms.symbol_indices)

# Index into the symbols, skipping over auxiliary records.  The resulting
# `symbol_number()` is the symbol's index within the symbol table.
function getindex(syms::COFFSymbols, idx)
    if !(0 < idx <= length(syms))
        throw(BoundsError(syms, idx))
    end
    oh = handle(syms)
    table_idx = syms.symbol_indices[idx]
    seek(oh, symtab_entry_offset(oh) + symtab_entry_size(oh)*(table_idx-1))
    return SymbolRef(syms, unpack(oh, symtab_entry_type(oh)), table_idx)
end

@io struct COFFSymtabEntry{H <: COFFHandle} <: SymtabEntry{H}
    Name::fixed_string{UInt64}
    Value::UInt32
    SectionNumber::Int16
    Type::UInt16
    StorageClass::UInt8
    NumberOfAuxSymbols::UInt8
end align_packed

function symbol_name(sym::COFFSymtabEntry)
    # COFF Symbols set the first four bytes of the name to zero to signify a
    # name that must be looked up in the string table
    if (sym.Name.data & 0xffffffff) == 0
        return string("strtab@", (sym.Name.data >> 32))
    end
    return unsafe_string(sym.Name)
end

symbol_value(sym::COFFSymtabEntry) = sym.Value
symbol_type(sym::COFFSymtabEntry) = sym.Type
function isundef(sym::COFFSymtabEntry)
    sym.StorageClass in (
        IMAGE_SYM_CLASS_EXTERNAL_DEF,
        IMAGE_SYM_CLASS_UNDEFINED_LABEL,
        IMAGE_SYM_CLASS_UNDEFINED_STATIC) ||
    (sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
     sym.SectionNumber == IMAGE_SYM_CLASS_NULL)
end
isglobal(sym::COFFSymtabEntry) = isundef(sym) || sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL
islocal(sym::COFFSymtabEntry) = !isglobal(sym)
isweak(sym::COFFSymtabEntry) = sym.StorageClass == IMAGE_SYM_CLASS_WEAK_EXTERNAL


"""
    COFFSymbolRef

Contains a reference to an `COFFSymtabEntry`, as well as an `COFFSymbols`, etc...
"""
struct COFFSymbolRef{H<:COFFHandle} <: SymbolRef{H}
    syms::COFFSymbols{H}
    entry::COFFSymtabEntry{H}
    idx::UInt32
end
function SymbolRef(syms::COFFSymbols, entry::COFFSymtabEntry, idx)
    return COFFSymbolRef(syms, entry, UInt32(idx))
end

deref(sym::COFFSymbolRef) = sym.entry
Symbols(sym::COFFSymbolRef) = sym.syms
symbol_number(sym::COFFSymbolRef) = sym.idx
symbol_section(sym::COFFSymbolRef) = Sections(handle(sym))[deref(sym).SectionNumber]
@derefmethod symbol_type(sym::COFFSymbolRef)
function symbol_name(sym::COFFSymbolRef)
    # COFF Symbols set the first four bytes of the name to zero to signify a
    # name that must be looked up in the string table
    name = deref(sym).Name
    if (name.data & 0xffffffff) == 0
        # If it's zeroes all the way down, just return an empty string
        if name.data == 0
            return ""
        end
        return strtab_lookup(StrTab(handle(sym)), (name.data >> 32))
    end
    return unsafe_string(name)
end

function symbol_offset(sym::COFFSymbolRef)
    # Return the offset into the file that this symbol refers to
    return symbol_value(sym) + section_offset(symbol_section(sym))
end

# Symbol printing stuff
"""
    symbol_type_string(s::COFFSymtabEntry)

Return the given `COFFSymtabEntry`'s section type as a string.
"""
function symbol_type_string(sym::COFFSymtabEntry)
    global IMAGE_SYM_TYPE

    # fast-track a zero symbol type
    if sym.Type == 0
        return ""
    end

    # We have to construct a compound type string here
    type_string = ""

    # We start with the "derived" type, e.g. pointer, array, etc...
    dtype = (sym.Type & 0xf0) >> 4
    if haskey(IMAGE_SYM_DTYPE, dtype)
        type_string = string("(", IMAGE_SYM_DTYPE[dtype], ")")
    end

    # Then, move on to the "base" type, e.g. void, char, short...
    btype = sym.Type & 0x0f
    if haskey(IMAGE_SYM_TYPE, btype)
        type_string = "$(type_string) $(IMAGE_SYM_TYPE[btype])"
    end

    # If we didn't get ANY info, complain
    if isempty(type_string)
        string("Unknown Symbol Type (0x", string(sym.Type, base=16), ")")
    end

    return type_string
end
@derefmethod symbol_type_string(s::COFFSymbolRef)
