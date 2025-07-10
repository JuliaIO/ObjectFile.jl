using ObjectFile, Base.BinaryPlatforms
using Test

@testset "basic" begin
    # Test that an empty file is a magic mismatch
    mktempdir() do dir
        fpath = joinpath(dir, "empty")
        touch(fpath)
        @test_throws MagicMismatch readmeta(fpath) do ohs
            @test false
        end
    end
end

function test_libfoo_and_fooifier(fooifier_path, libfoo_path)
    # Actually read it in
    oh_exe = only(readmeta(open(fooifier_path, "r")))
    oh_lib = only(readmeta(open(libfoo_path, "r")))

    # Tease out some information from the containing folder name
    dir_path = basename(dirname(libfoo_path))
    types = Dict(
        "linux" => ELFHandle,
        "mac" => MachOHandle,
        "win" => COFFHandle,
    )

    platform = dir_path[1:end-2]
    H = types[platform]
    bits = dir_path[end-1:end]

    platforms = Dict(
        "linux32" => Platform("i686", "linux"),
        "linux64" => Platform("x86_64", "linux"),
        "mac64" => Platform("x86_64", "macos"),
        "win32" => Platform("i686", "windows"),
        "win64" => Platform("x86_64", "windows"),
    )

    @testset "$(dir_path)" begin
        @testset "General Properties" begin
            for oh in (oh_exe, oh_lib)
                # Test that we got the right type
                @test typeof(oh) <: H

                # Test that we got the right number of bits
                @test is64bit(oh) == (bits == "64")
                @test platforms_match(Platform(oh), platforms[dir_path])

                # Everything is always little endian
                @test endianness(oh) == :LittleEndian
            end

            # None of these are .o files
            @test !isrelocatable(oh_exe)
            @test !isrelocatable(oh_lib)

            # Ensure these are the kinds of files we thought they were
            @test isexecutable(oh_exe)
            @test islibrary(oh_lib)
            @test isdynamic(oh_exe) && isdynamic(oh_lib)
        end


        @testset "Dynamic Linking" begin
            # Ensure that `dir_path` is one of the RPath entries
            rpath = RPath(oh_exe)
            can_paths = canonical_rpaths(rpath)
            @test abspath(dir_path * Base.Filesystem.path_separator) in can_paths

            # Ensure that `fooifier` is going to try to load `libfoo`:
            foo_libs = find_libraries(oh_exe)
            @test !isempty(foo_libs)
            @test abspath(libfoo_path) in values(foo_libs)
        end

        # Ensure that `foo()` is referenced in both, defined in `libfoo`, and
        # not defined in `fooifier`.  Also ensure that `_main` is defined in
        # `fooifier` and is not present in `libfoo`.
        @testset "Symbols" begin
            syms_exe = collect(Symbols(oh_exe))
            syms_lib = collect(Symbols(oh_lib))

            syms_names_exe = symbol_name.(syms_exe)
            syms_names_lib = symbol_name.(syms_lib)

            # ELF stores the symbol name as "foo", MachO stores it as "_foo"
            foo_sym_name = mangle_symbol_name(oh_exe, "foo")
            main_sym_name = mangle_symbol_name(oh_exe, "main")

            @test foo_sym_name in syms_names_exe
            @test foo_sym_name in syms_names_lib
            @test main_sym_name in syms_names_exe
            @test !(main_sym_name in syms_names_lib)

            foo_idx_exe = findfirst(syms_names_exe .== foo_sym_name)
            main_idx_exe = findfirst(syms_names_exe .== main_sym_name)
            foo_idx_lib = findfirst(syms_names_lib .== foo_sym_name)

            @test foo_idx_exe != 0
            @test main_idx_exe != 0
            @test foo_idx_lib != 0

            # definedness doesn't seem to be for COFF files...
            if !isa(oh_exe, COFFHandle)
                @test isundef(syms_exe[foo_idx_exe])
                @test !isundef(syms_exe[main_idx_exe])
                @test !isundef(syms_lib[foo_idx_lib])
            end

            @test !islocal(syms_exe[foo_idx_exe])
            @test !islocal(syms_exe[main_idx_exe])
            @test !islocal(syms_lib[foo_idx_lib])

            # Global detection doesn't seem to be working on OSX...
            if !isa(oh_exe, MachOHandle)
                @test isglobal(syms_exe[foo_idx_exe])
                @test isglobal(syms_exe[main_idx_exe])
                @test isglobal(syms_lib[foo_idx_lib])
            end
        end

        @testset "Printing" begin
            # Print out to an IOContext that will limit long lists
            io = IOContext(stdout, :limit => true)

            # Helper that shows the type, then the value:
            function tshow(x)
                type_name = typeof(x).name.name
                println(io, "INFO: Showing $(type_name)")
                show(io, x)
                print(io, "\n")
            end

            # Show printing of a Handle
            tshow(oh_lib)

            # Test showing of the header
            tshow(header(oh_lib))

            # Test showing of Sections
            sects = Sections(oh_exe)
            tshow(sects)
            tshow(sects[1])

            # Test showing of Segments on non-COFF
            if !isa(oh_exe, COFFHandle)
                segs = Segments(oh_lib)
                tshow(segs)
                tshow(segs[1])
            end

            # Test showing of Symbols
            syms = Symbols(oh_exe)
            tshow(syms)
            tshow(syms[1])

            # Test showing of RPath and DynamicLinks
            rpath = RPath(oh_exe)
            tshow(rpath)

            dls = DynamicLinks(oh_exe)
            tshow(dls)
            tshow(dls[1])
        end
    end
end

function test_fat_libfoo(file)
    ohs = readmeta(open(file, "r"))
    @test isa(ohs, FatMachOHandle)
    @test length(ohs) == 2
    ntotal, n64 = 0, 0
    for oh in ohs
        ntotal += 1
        n64 += is64bit(oh)
    end
    @test ntotal == 2
    @test n64 == 1
end

function test_metal(file)
    ohs = readmeta(open(file, "r"))
    @test isa(ohs, FatMachOHandle)
    @test length(ohs) == 2

    let oh = ohs[1]
        @test oh.header isa MachO.MachOHeader64
        @test findfirst(Sections(oh), "__TEXT,__compute") !== nothing
    end

    let oh = ohs[2]
        @test oh.header isa MachO.MetallibHeader
    end
end

# Run ELF tests
test_libfoo_and_fooifier("./linux32/fooifier", "./linux32/libfoo.so")
test_libfoo_and_fooifier("./linux64/fooifier", "./linux64/libfoo.so")

# Run MachO tests
test_libfoo_and_fooifier("./mac64/fooifier", "./mac64/libfoo.dylib")
test_fat_libfoo("./mac64/libfoo_fat.dylib")
test_metal("./macmetal/dummy")

# Run COFF tests
test_libfoo_and_fooifier("./win32/fooifier.exe", "./win32/libfoo.dll")
test_libfoo_and_fooifier("./win64/fooifier.exe", "./win64/libfoo.dll")


# Ensure that ELF version stuff works
@testset "ELF Version Info Parsing" begin
    using ObjectFile.ELF

    # Assuming the version structs in the file are correct, test that we read
    # them correctly (and calculate hashes correctly).
    function check_verdef(v::ELF.ELFVersionEntry)
        @test v.ver_def.vd_version == 1
        @test v.ver_def.vd_cnt == length(v.names)
        if length(v.names) > 0
            @test v.ver_def.vd_hash == ELFHash(Vector{UInt8}(v.names[1]))
        end
    end
    function check_verneed(v::ELF.ELFVersionNeededEntry)
        @test v.ver_need.vn_version == 1
        @test v.ver_need.vn_cnt == length(v.auxes) == length(v.names)
        for i in 1:length(v.names)
            @test v.auxes[i].vna_hash == ELFHash(Vector{UInt8}(v.names[i]))
        end
    end

    libstdcxx_path = "./linux64/libstdc++.so.6"

    # Extract all pieces of `.gnu.version_d` from libstdc++.so, find the `GLIBCXX_*`
    # symbols, and use the maximum version of that to find the GLIBCXX ABI version number
    readmeta(libstdcxx_path) do ohs
        oh = only(ohs)
        verdef_symbols = unique(vcat((x -> x.names).(ELFVersionData(oh))...))
        verdef_symbols = filter(x -> startswith(x, "GLIBCXX_"), verdef_symbols)
        max_version = maximum([VersionNumber(split(v, "_")[2]) for v in verdef_symbols])
        @test max_version == v"3.4.25"
    end

    for p in ["./linux32/fooifier", "./linux32/libfoo.so",
              "./linux64/fooifier", "./linux64/libfoo.so",
              "./linux64/libstdc++.so.6"]
        readmeta(p) do ohs
            oh = only(ohs)
            foreach(check_verdef, ELFVersionData(oh))
            foreach(check_verneed, ELFVersionNeededData(oh))
        end
    end

end

# Ensure that these tricksy win32 files work
@testset "git win32 problems" begin
    # Test that 6a66694a8dd5ca85bd96fe6236f21d5b183e7de6 fix worked
    libmsobj_path = "./win32/msobj140.dll"

    dynamic_links = readmeta(libmsobj_path) do ohs
        oh = only(ohs)
        path.(DynamicLinks(oh))
    end

    @test "KERNEL32.dll" in dynamic_links
    @test "api-ms-win-crt-heap-l1-1-0.dll" in dynamic_links
    @test "api-ms-win-crt-convert-l1-1-0.dll" in dynamic_links
    @test "api-ms-win-crt-runtime-l1-1-0.dll" in dynamic_links

    whouses_exe = "./win32/WhoUses.exe"
    dynamic_links = readmeta(whouses_exe) do ohs
        oh = only(ohs)
        path.(DynamicLinks(oh))
    end

    @test "ADVAPI32.dll" in dynamic_links
    @test "KERNEL32.dll" in dynamic_links
    @test "libstdc++-6.dll" in dynamic_links
end

using Mmap
@testset "Finding dep_libs" begin
    function find_dep_libs(file)
        obj = only(readmeta(open(file, "r")))
        syms = collect(Symbols(obj))
        syms_names = symbol_name.(syms)
        sym = syms[findfirst(syms_names .== mangle_symbol_name(obj, "dep_libs"))]
        offset = symbol_offset(sym)
        filem = Mmap.mmap(file)
        data = String(filem[offset: (offset + 255)])
        @test contains(data, "libjulia-internal")
        @test contains(data, "libjulia-codegen")
        @test contains(data, "libopenlibm")
    end
    for file in readdir("./libjulias")
        find_dep_libs(joinpath("./libjulias", file))
    end
end

