cmake_minimum_required(VERSION 3.15.0)
cmake_policy(SET CMP0091 NEW)
project(yara VERSION 4.1.3)

find_package (Threads)
# FIXME: Consider defining - HAVE_CLOCK_GETTIME=1, HAVE_MEMMEM=1, HAVE_STDBOOL_H=1, HAVE_TIMEGM=1, HAVE_SCAN_PROC_IMPL=1

add_library(libyara STATIC libyara/modules/module_list
                           libyara/endian.c
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
                           libyara/proc/linux.c
                           libyara/proc/mach.c
                           libyara/hash.c
                           libyara/modules/ole/ole.cpp
                           #libyara/tests.c
                           #cuckoo.c
                           #hash
)

target_compile_options(libyara PRIVATE ${TURN_OFF_WARNINGS_AS_ERRORS_COMPILE_FLAG}
                                       ${NO_WARNINGS_COMPILE_FLAG})
target_include_directories(libyara PUBLIC libyara/include
                                   PRIVATE libyara)
target_link_libraries(libyara ${CMAKE_THREAD_LIBS_INIT} Pole)

if (WIN32)
    set_target_properties(libyara PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(OS_SPECIFIC_DEFINITIONS USE_WINDOWS_PROC)
else()
    if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux")
        set(OS_SPECIFIC_DEFINITIONS USE_LINUX_PROC HAVE_MEMMEM=1)
    elseif(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Darwin")
        set(OS_SPECIFIC_DEFINITIONS USE_MACH_PROC HAVE_MEMMEM=1)
    endif()
endif()

target_compile_definitions(libyara PRIVATE ${OS_SPECIFIC_DEFINITIONS} HAVE_CLOCK_GETTIME=1
                                           HAVE_STDBOOL_H=1 HAVE_TIMEGM=1 HAVE_SCAN_PROC_IMPL=1)
