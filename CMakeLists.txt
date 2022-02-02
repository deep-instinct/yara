cmake_minimum_required(VERSION 3.15.0)
cmake_policy(SET CMP0091 NEW)
project(yara VERSION 4.1.3)

# FIXME: Consider defining - HAVE_CLOCK_GETTIME=1, HAVE_MEMMEM=1, HAVE_STDBOOL_H=1, HAVE_TIMEGM=1, HAVE_SCAN_PROC_IMPL=1, oneof(USE_MACH_PROC, USE_LINUX_PROC, USE_WINDOWS_PROC)

add_library(libyara STATIC libyara/modules/module_list
                           libyara/ahocorasick.c
                           libyara/arena.c
                           libyara/atoms.c
                           libyara/base64.c
                           libyara/bitmask.c
                           libyara/compiler.c
                           libyara/modules/dex/dex.c
                           libyara/modules/dotnet/dotnet.c
                           libyara/modules/elf/elf.c
                           libyara/exec.c
                           libyara/exefiles.c
                           libyara/filemap.c
                           libyara/grammar.c
                           libyara/hex_grammar.c
                           libyara/hex_lexer.c
                           libyara/lexer.c
                           libyara/libyara.c
                           libyara/modules/macho/macho.c
                           libyara/modules/math/math.c
                           libyara/mem.c
                           libyara/modules.c
                           libyara/notebook.c
                           libyara/object.c
                           libyara/parser.c
                           libyara/modules/pe/pe.c
                           libyara/modules/pe/pe_utils.c
                           libyara/proc.c
                           libyara/re.c
                           libyara/re_grammar.c
                           libyara/re_lexer.c
                           libyara/rules.c
                           libyara/scan.c
                           libyara/scanner.c
                           libyara/sizedstr.c
                           libyara/stack.c
                           libyara/stopwatch.c
                           libyara/stream.c
                           libyara/strutils.c
                           libyara/threading.c
                           libyara/modules/time/time.c
                           libyara/proc/windows.c
                           libyara/hash.c
                           #libyara/tests.c
                           #cuckoo.c
                           #hash
)

target_compile_options(libyara PRIVATE "${TURN_OFF_WARNINGS_COMPILE_FLAGS}")
target_include_directories(libyara PUBLIC libyara/include
                                   PRIVATE libyara)

if (WIN32)
    set_target_properties(libyara PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(libyara PRIVATE USE_WINDOWS_PROC)
endif()
