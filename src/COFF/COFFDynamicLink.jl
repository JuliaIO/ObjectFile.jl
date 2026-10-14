export COFFDynamicLinks, COFFDynamicLink, COFFRPath

struct COFFDynamicLink{H <: COFFHandle} <: DynamicLink{H}
    path::String
end
path(dl::COFFDynamicLink) = dl.path


@io struct COFFImageImportDescriptor
    Characteristics::UInt32
    TimeDateStamp::UInt32
    ForwarderChain::UInt32
    Name::UInt32
    FirstThunk::UInt32
end

struct COFFDynamicLinks{H <: COFFHandle} <: DynamicLinks{H}
    handle::H
    links::Vector
end

function import_name(oh::COFFHandle, idata::COFFSectionRef, iid)
    seek(oh, iid.Name - section_address(idata) + section_offset(idata))
    return strip(readuntil(oh, '\0'), '\0')
end

function find_section_for_rva(oh::H, rva) where {H <: COFFHandle}
    for s in Sections(oh)
        if section_address(s) <= rva && section_address(s) + section_size(s) > rva
            return s
        end
    end
    error("Unable to find section for RVA $(repr(rva))")
end

function COFFDynamicLinks(oh::H) where {H <: COFFHandle}
    # Object files are not loaded, and so have no import table
    if oh.opt_header === nothing
        return COFFDynamicLinks(oh, COFFDynamicLink{H}[])
    end

    # Start by finding the virtual address of the import table
    import_table_rva = oh.opt_header.directories.ImportTable.VirtualAddress

    # Next figure out which section that belongs to:
    s = find_section_for_rva(oh, import_table_rva)

    # We'll load in all the ImageImportDescriptors we can
    iids = COFFImageImportDescriptor[]

    # Read in ImageImportDescriptors until it's all NULL
    seek(oh, (import_table_rva - section_address(s)) +  section_offset(s))
    while true
        iid = unpack(oh, COFFImageImportDescriptor)
        if iid.Name == 0 && iid.FirstThunk == 0 && iid.Characteristics == 0 && iid.ForwarderChain == 0 && iid.TimeDateStamp == 0
            break
        else
            push!(iids, iid)
        end
    end

    # Now, jump around and get all the strings
    links = [COFFDynamicLink{H}(import_name(oh, s, iid)) for iid in iids]
    return COFFDynamicLinks(oh, links)
end
DynamicLinks(oh::COFFHandle) = COFFDynamicLinks(oh)

handle(dls::COFFDynamicLinks) = dls.handle
lastindex(dls::COFFDynamicLinks) = lastindex(dls.links)
getindex(dls::COFFDynamicLinks, idx) = getindex(dls.links, idx)


"""
    COFFRPath

COFF RPath object; note that while COFF files do not have an RPath within them,
they _do_ seach the same directory as the loading binary (e.g. the `\$ORIGIN`).
We use `COFFRPath` to effect this, although strictly speaking there is no such
thing as a "COFF RPath".
"""
struct COFFRPath{H <: COFFHandle} <: RPath{H}
    handle::H
end

RPath(oh::COFFHandle) = COFFRPath(oh)
handle(crp::COFFRPath) = crp.handle
rpaths(crp::COFFRPath) = String[]

# COFF files don't have an RPath, but they _do_ always search the $ORIGIN
function canonical_rpaths(crp::COFFRPath)
    return [abspath(dirname(path(handle(crp))) * "/")]
end
