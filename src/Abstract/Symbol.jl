# Note that since Base Julia already has a `Symbol` object, we use the term
# `SymtabEntry` to refer to the concrete instantiation of a symbol within an
# object file, and the term `SymbolRef` as a reference to that object.

# Export Symbols API
export Symbols,
       getindex, endof, length, start, next, done, eltype,
       handle, header
       
# Export SymtabEntry API
export SymtabEntry,
       deref, symbol_name, symbol_value, isundef, isglobal, islocal, isweak

# Export SymbolRef API
export SymbolRef,
       symbol_number


"""
    Symbols

An abstraction over the concept of a collection of symbol (`SymtabEntry`) types
within an object file.  One can think of the `Symbols` object containing the
table of symbols within the object file, whereas the `SymtabEntry`/`SymbolRef`
objects contain the actual symbol data itself.  The list of available API
operations is given below, with methods that subclasses must implement marked
in emphasis:

### Creation
  - *Symbols()*

### Iteration
  - getindex()
  - *endof()*
  - length()
  - start()
  - next()
  - done()
  - eltype()

### Misc.
  - *handle()*
"""
abstract type Symbols{H<:ObjectHandle} end

# Fairly simple iteration interface specification
@mustimplement endof(syms::Symbols)
start(syms::Symbols) = 1
done(syms::Symbols, idx) = idx > length(syms)
next(syms::Symbols, idx) = (syms[idx], idx+1)
length(syms::Symbols) = endof(syms)
eltype(::Type{S}) where {S <: Symbols} = SymbolRef

function getindex(syms::Symbols{H}, idx) where {H <: ObjectHandle}
    # Punt off to `getindex_ref`
    oh = handle(syms)
    return getindex_ref(
        syms,
        symtab_entry_offset(oh),
        symtab_entry_size(oh),
        symtab_entry_type(oh),
        SymbolRef,
        idx
    )
end





"""
    SymtabEntry

An abstraction over the concept of a symbol within an object file.  This type
does not use the `Symbol` name as this would conflict with the builtin Julia
`Symbol` type, so the name `SymtabEntry` is used instead.  As a user, the
`SymbolRef` type should be the primary method of interacting with symbols, as a
developer adding new object file formats, some methods must support
`SymtabEntry`s, others must support only `SymbolRef`s.  Note that any method
that works on a `SymtabEntry` must also work with a `SymbolRef`, see the
`@derefmethod` macro for a convenient helper macro to generate `SymbolRef` ->
`SymtabEntry` wrapper methods. The list of available API operations is given
below, with methods that subclasses must implement marked in emphasis:

### Creation:
  - *SymtabEntry()*

### Util:
  - deref()

### Properties:
  - *symbol_name()*
  - *symbol_value()*
  - *isundef()*
  - *isglobal()*
  - *islocal()*
  - *isweak()*
"""
abstract type SymtabEntry{H<:ObjectHandle} end

# Dummy `deref()`
deref(sym::SymtabEntry) = sym

"""
    symbol_name(sym::SymtabEntry)

Return the name of the given section as a string.  In order to return a true
name, it is necessary to perform a lookup within the object's string table,
which cannot be done using just a `SymtabEntry` object; use a `SymbolRef`
object instead if you need that.  For sanity sake, this method will return a
string, but the contents of the string may be something like the offset within
the string table pointing to this `SymtabEntry`'s name, e.g. "@strtab.123"
"""
@mustimplement symbol_name(sym::SymtabEntry)

"""
    symbol_value(sym::SymtabEntry)

Return the value of the given symbol
"""
@mustimplement symbol_value(sym::SymtabEntry)

"""
    isundef(sym::SymtabEntry)

Return `true` if the given symbol is undefined
"""
@mustimplement isundef(sym::SymtabEntry)

"""
    isglobal(sym::SymtabEntry)

Return `true` if the given symbol is global
"""
@mustimplement isglobal(sym::SymtabEntry)

"""
    islocal(sym::SymtabEntry)

Return `true` if the given symbol is local
"""
@mustimplement islocal(sym::SymtabEntry)

"""
    isweak(sym::SymtabEntry)

Return `true` if the given symbol is weak
"""
@mustimplement isweak(sym::SymtabEntry)





"""
    SymbolRef

Provides a reference to a `SymtabEntry`, along with a reference to the
`ObjectHandle` this `SymtabEntry` comes from.  This should be the primary
method by which users interact with symbols inside object files.  The list of
available API operations is given below, with methods that subclasses must
implement marked in emphasis.  Note that this overlaps heavily with the
`SymtabEntry` object API, this is by design as many of the methods are simply
passthroughs to the underlying `SymtabEntry` API calls for ease of use.

### Creation:
  - *SymbolRef()*

### Util:
  - *deref()*
  - *Symbols()*
  - handle()

### Properties:
  - *symbol_number()*
  - *symbol_name()*
  - symbol_value()
  - isundef()
"""

abstract type SymbolRef{H<:ObjectHandle} end

"""
SymbolRef(symbols::Symbols, sym::SymtabEntry, idx::UInt32)

Construct a `SymbolRef` object pointing to the given `SymtabEntry`, which
itself represents the `idx`'th symbol within the given `Symbols` collection.
"""
@mustimplement SymbolRef(symbols::Symbols, sym::SymtabEntry, idx::UInt32)
@mustimplement deref(sym::SymbolRef)

"""
    Symbols(sym::SymbolRef)

Return the `Symbols` object that this `SymbolRef` belongs to.
"""
@mustimplement Symbols(sym::SymbolRef)

"""
    handle(sym::SymbolRef)

Return the `ObjectHandle` that this `SymbolRef` belongs to.
"""
handle(sym::SymbolRef) = handle(Symbols(sym))

"""
    symbol_number(sym::SymbolRef)

Return the number (index) of the given symbol.
"""
@mustimplement symbol_number(sym::SymbolRef)

"""
    symbol_name(sym::SymbolRef)

Return the name of the given symbol as a string.  This method often performs
some kind of lookup within the string table of the object to get the full name
of the symbol.
"""
@mustimplement symbol_name(sym::SymbolRef)

@derefmethod symbol_value(sym::SymbolRef)
@derefmethod isundef(sym::SymbolRef)
@derefmethod isglobal(sym::SymbolRef)
@derefmethod islocal(sym::SymbolRef)
@derefmethod isweak(sym::SymbolRef)