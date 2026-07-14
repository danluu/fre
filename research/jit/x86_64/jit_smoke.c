/* Minimal Rosetta/native W^X diagnostic; not part of FRE. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

typedef uint32_t (*entry_fn)(void);

int main(void) {
    int translated = 0;
    size_t translated_size = sizeof(translated);
    int translated_status =
        sysctlbyname("sysctl.proc_translated", &translated, &translated_size,
                     NULL, 0);
    if (translated_status == 0) {
        if (translated == 1) {
            fprintf(stderr,
                    "refusing raw mprotect JIT probe under Rosetta; use a "
                    "qualified MAP_JIT publisher\n");
            return 2;
        }
    } else if (errno != ENOENT) {
        perror("sysctl.proc_translated");
        return 2;
    }
    static const uint8_t code[] = {0xB8, 0x7B, 0x00, 0x00, 0x00, 0xC3};
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *memory = mmap(NULL, page, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    memcpy(memory, code, sizeof(code));
    if (mprotect(memory, page, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        return 2;
    }
    sys_icache_invalidate(memory, sizeof(code));
    entry_fn entry = (entry_fn)memory;
    uint32_t result = entry();
    printf("result=%u\n", result);
    return result == 123 ? 0 : 1;
}
