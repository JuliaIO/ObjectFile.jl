export MachOVersionMinCmd, MachOBuildVersionCmd

export min_os_version, sdk_version, build_platform

"""
    macho_version(v::UInt32)

Decode a Mach-O packed version number, stored as `xxxx.yy.zz` in nibbles
(16 bits of major version, 8 bits each of minor and patch version), into a
`VersionNumber`.
"""
macho_version(v::UInt32) = VersionNumber(v >> 16, (v >> 8) & 0xff, v & 0xff)

@io struct MachOVersionMinStub
    version::UInt32
    sdk::UInt32
end

"""
    MachOVersionMinCmd

The Load Command that records the minimum OS version and the SDK version an
object was built for, used by the `LC_VERSION_MIN_MACOSX`,
`LC_VERSION_MIN_IPHONEOS`, `LC_VERSION_MIN_TVOS` and `LC_VERSION_MIN_WATCHOS`
load commands.  Newer toolchains emit `MachOBuildVersionCmd` instead.

### Accessors:
  - min_os_version()
  - sdk_version()
  - build_platform()
"""
struct MachOVersionMinCmd{H <: MachOHandle} <: MachOLoadCmd{H}
    cmd::UInt32
    version::UInt32
    sdk::UInt32
end

function MachOLoadCmd(oh::H, CT::Type{CTT}, header) where {CTT <: MachOVersionMinCmd} where {H <: MachOHandle}
    stub = unpack(oh, MachOVersionMinStub)
    return CT(header.cmd & ~LC_REQ_DYLD, stub.version, stub.sdk)
end

show(io::IO, lc::MachOVersionMinCmd) = write(io, "VersionMinCmd: $(PLATFORMS[build_platform(lc)]) $(min_os_version(lc)) (SDK $(sdk_version(lc)))")

"""
    MachOBuildVersionCmd

The Load Command (`LC_BUILD_VERSION`) that records the platform, minimum OS
version and SDK version an object was built for.  The list of build tool
versions that follows the fixed-size part of the command is not read.

### Accessors:
  - min_os_version()
  - sdk_version()
  - build_platform()
"""
@io struct MachOBuildVersionCmd{H <: MachOHandle} <: MachOLoadCmd{H}
    platform::UInt32
    minos::UInt32
    sdk::UInt32
    ntools::UInt32
end

function show(io::IO, lc::MachOBuildVersionCmd)
    platform = get(PLATFORMS, build_platform(lc), "Unknown Platform ($(build_platform(lc)))")
    write(io, "BuildVersionCmd: $(platform) $(min_os_version(lc)) (SDK $(sdk_version(lc)))")
end

const VersionCmd = Union{MachOVersionMinCmd, MachOBuildVersionCmd}

"""
    min_os_version(cmd::Union{MachOVersionMinCmd, MachOBuildVersionCmd})

Return the minimum OS version recorded in the given Load Command, as a
`VersionNumber`.
"""
min_os_version(cmd::MachOVersionMinCmd) = macho_version(cmd.version)
min_os_version(cmd::MachOBuildVersionCmd) = macho_version(cmd.minos)

"""
    sdk_version(cmd::Union{MachOVersionMinCmd, MachOBuildVersionCmd})

Return the SDK version recorded in the given Load Command, as a
`VersionNumber`.
"""
sdk_version(cmd::VersionCmd) = macho_version(cmd.sdk)

"""
    build_platform(cmd::Union{MachOVersionMinCmd, MachOBuildVersionCmd})

Return the `PLATFORM_*` constant identifying the platform the given Load
Command targets.  For `MachOVersionMinCmd`, the platform is implied by the
load command type.
"""
build_platform(cmd::MachOBuildVersionCmd) = cmd.platform
function build_platform(cmd::MachOVersionMinCmd)
    cmd.cmd == LC_VERSION_MIN_MACOSX && return UInt32(PLATFORM_MACOS)
    cmd.cmd == LC_VERSION_MIN_IPHONEOS && return UInt32(PLATFORM_IOS)
    cmd.cmd == LC_VERSION_MIN_TVOS && return UInt32(PLATFORM_TVOS)
    cmd.cmd == LC_VERSION_MIN_WATCHOS && return UInt32(PLATFORM_WATCHOS)
    throw(ArgumentError("Unknown LC_VERSION_MIN_* load command 0x$(string(cmd.cmd, base=16))"))
end

@derefmethod min_os_version(cmd::MachOLoadCmdRef{H, T}) where {H <: MachOHandle} where {T <: VersionCmd}
@derefmethod sdk_version(cmd::MachOLoadCmdRef{H, T}) where {H <: MachOHandle} where {T <: VersionCmd}
@derefmethod build_platform(cmd::MachOLoadCmdRef{H, T}) where {H <: MachOHandle} where {T <: VersionCmd}

"""
    version_cmd(oh::MachOHandle)

Return the first `MachOBuildVersionCmd` or `MachOVersionMinCmd` Load Command
within `oh`, or `nothing` if it has neither.
"""
function version_cmd(oh::MachOHandle)
    for cmd in MachOLoadCmds(oh)
        cmd isa VersionCmd && return cmd
    end
    return nothing
end

"""
    min_os_version(oh::MachOHandle)

Return the minimum OS version that the Mach-O object `oh` was built for, as
recorded in its `LC_BUILD_VERSION` or `LC_VERSION_MIN_*` Load Command, as a
`VersionNumber`.  Returns `nothing` if the object records no such version.
"""
function min_os_version(oh::MachOHandle)
    cmd = version_cmd(oh)
    return cmd === nothing ? nothing : min_os_version(cmd)
end

"""
    sdk_version(oh::MachOHandle)

Return the SDK version that the Mach-O object `oh` was built against, as
recorded in its `LC_BUILD_VERSION` or `LC_VERSION_MIN_*` Load Command, as a
`VersionNumber`.  Returns `nothing` if the object records no such version.
"""
function sdk_version(oh::MachOHandle)
    cmd = version_cmd(oh)
    return cmd === nothing ? nothing : sdk_version(cmd)
end

"""
    build_platform(oh::MachOHandle)

Return the `PLATFORM_*` constant identifying the platform that the Mach-O
object `oh` was built for, as recorded in its `LC_BUILD_VERSION` or
`LC_VERSION_MIN_*` Load Command.  Returns `nothing` if the object records no
such information.
"""
function build_platform(oh::MachOHandle)
    cmd = version_cmd(oh)
    return cmd === nothing ? nothing : build_platform(cmd)
end
