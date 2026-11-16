export MachODynamicLinks, MachODynamicLink, MachORPath

struct MachODynamicLinks{H <: MachOHandle, C <: MachOLoadCmdRef{H,MachOLoadDylibCmd{H}}} <: DynamicLinks{H}
    handle::H
    cmds::Vector{C}
end

function MachODynamicLinks(lcs::MachOLoadCmds{H}) where {H <: MachOHandle}
    ld_cmds = MachOLoadCmdRef{H,MachOLoadDylibCmd{H}}[c for c in findall(lcs, [MachOLoadDylibCmd])]
    return MachODynamicLinks(handle(lcs), ld_cmds)
end
MachODynamicLinks(oh::MachOHandle) = MachODynamicLinks(MachOLoadCmds(oh))

DynamicLinks(oh::MachOHandle) = MachODynamicLinks(oh)
DynamicLinks(lcs::MachOLoadCmds) = MachODynamicLinks(lcs)

lastindex(dls::MachODynamicLinks) = lastindex(dls.cmds)
function getindex(dls::MachODynamicLinks, idx)
    return MachODynamicLink(dls, dls.cmds[idx])
end
handle(dls::MachODynamicLinks) = dls.handle

"""
    MachODynamicLink

MachO type representing a dynamic link between a MachO file and one of its
dynamic dependencies.  Although Mach-O encodes more than just the path of the
dependency, in order to get at it you will need to dig into the LoadCmd that
describes it.
"""
struct MachODynamicLink{H <: MachOHandle} <: DynamicLink{H}
    dls::MachODynamicLinks
    cmd_ref::MachOLoadCmdRef{H,MachOLoadDylibCmd{H}}
end

DynamicLinks(dl::MachODynamicLink) = dl.dls
handle(dl::MachODynamicLink) = handle(DynamicLinks(dl))
path(dl::MachODynamicLink) = dylib_name(deref(dl.cmd_ref))


struct MachORPath{H <: MachOHandle} <: RPath{H}
    handle::H
    cmds::Vector
end

function MachORPath(lcs::MachOLoadCmds)
    cmds = findall(lcs, [MachORPathCmd])
    return MachORPath(handle(lcs), cmds)
end

RPath(oh::MachOHandle) = MachORPath(oh)
MachORPath(oh::MachOHandle) = MachORPath(MachOLoadCmds(oh))
handle(mrp::MachORPath) = mrp.handle

function rpaths(mrp::MachORPath)
    return [rpath(c) for c in mrp.cmds]
end
