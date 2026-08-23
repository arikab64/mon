find_program(BPFTOOL bpftool REQUIRED)
find_program(CLANG clang REQUIRED)
# Rust skeletons come from libbpf-cargo; bpftool's own `gen skeleton` is C-only.
find_program(CARGO cargo REQUIRED)

set(VMLINUX ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h)

# Where staged build outputs live, shared with src/mon. CMAKE_BINARY_DIR (top
# of the build tree) on purpose, not CMAKE_CURRENT_BINARY_DIR.
set(MON_OUTPUT_DIR ${CMAKE_BINARY_DIR}/var/mon)

# Map the host machine to the BPF target arch (x86_64 -> x86, aarch64 -> arm64)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(BPF_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_ARCH arm64)
else()
    set(BPF_ARCH ${CMAKE_SYSTEM_PROCESSOR})
endif()

add_custom_command(
    OUTPUT ${VMLINUX}
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX}
    COMMENT "GEN ${VMLINUX}"
    VERBATIM
)
add_custom_target(vmlinux DEPENDS ${VMLINUX})

# add_bpf_program(<name>) compiles <name>.c to mon.<name>.o and generates the
# Rust skeleton <name>.skel.rs next to it, for the userspace loader to include!().
function(add_bpf_program name)
    set(obj ${CMAKE_CURRENT_BINARY_DIR}/mon.${name}.o)
    # Generated next to the BPF sources so the Rust code can pull it in with
    # a plain module directive (no build.rs indirection).
    set(skel ${CMAKE_CURRENT_SOURCE_DIR}/${name}.skel.rs)
    set(obj_staged ${MON_OUTPUT_DIR}/mon.${name}.o)
    add_custom_command(
        OUTPUT ${obj}
        COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
                -I${CMAKE_CURRENT_SOURCE_DIR}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/${name}.c -o ${obj}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${name}.c ${VMLINUX}
        COMMENT "BPF ${obj}"
        VERBATIM
    )
    # --object reads the prebuilt .o and writes the skeleton to stdout, so this
    # reuses the clang output above instead of recompiling the program.
    add_custom_command(
        OUTPUT ${skel}
        COMMAND ${CARGO} libbpf gen --object ${obj} > ${skel}
        DEPENDS ${obj}
        COMMENT "SKEL ${skel}"
        VERBATIM
    )
    # Stage the object at build/var/mon/, alongside the mon binary.
    add_custom_command(
        OUTPUT ${obj_staged}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${MON_OUTPUT_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy ${obj} ${obj_staged}
        DEPENDS ${obj}
        COMMENT "STAGE ${obj_staged}"
        VERBATIM
    )
    add_custom_target(mon_${name} ALL DEPENDS ${obj_staged} ${skel})
endfunction()

add_bpf_program(proc)
