module ObjectFile
using Reexport
import Base.BinaryPlatforms: Platform

# Include base utilities
include("utils.jl")
include("string_utils.jl")

# Include our Abstract definitions
include("Abstract/Abstract.jl")

# Include ELF format
include("ELF/ELF.jl")
@reexport using .ELF

# Include MachO format
include("MachO/MachO.jl")
@reexport using .MachO

# Include COFF format
include("COFF/COFF.jl")
@reexport using .COFF

# Include static archives (`ar`), which hold object files of the above formats
include("Archive/Archive.jl")
@reexport using .Archive

function __init__()
    global ObjTypes

    push!(ObjTypes, ELFHandle)
    push!(ObjTypes, MachOHandle)
    push!(ObjTypes, FatMachOHandle)
    push!(ObjTypes, COFFHandle)
    # `ArchiveHandle` is deliberately not registered: `readmeta(io)` returns
    # object files, and an archive is a collection of them.
end

end #module ObjectFile
