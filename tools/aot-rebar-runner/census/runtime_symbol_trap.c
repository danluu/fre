/* Runtime trap used only by the public-Rebar true-native census.
 *
 * The controller independently inventories the final executable and supplies
 * the complete semantic-helper set, or one claimed operation entry, through
 * FRE_AOT_CENSUS_TRAP_SYMBOLS.  This constructor patches every requested
 * symbol before main.  A caught BRK/UD2 exits with the dedicated status 197
 * after appending the exact triggered symbol to the marker.
 */

#define _GNU_SOURCE 1

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

#define MAX_TRAPS 512
#define MAX_SYMBOL_BYTES 255
#define TRAP_EXIT 197
#define CONTROL_EXIT 201

struct installed_trap {
    void *address;
    char symbol[MAX_SYMBOL_BYTES + 1];
    char triggered_line[MAX_SYMBOL_BYTES + 16];
    size_t triggered_line_length;
};

static struct installed_trap traps[MAX_TRAPS];
static size_t trap_count;
static int marker_descriptor = -1;

static void write_all(int descriptor, const char *data, size_t length) {
    while (length != 0) {
        ssize_t written = write(descriptor, data, length);
        if (written <= 0) {
            _exit(CONTROL_EXIT);
        }
        data += (size_t)written;
        length -= (size_t)written;
    }
}

static void fail(const char *operation) {
    char buffer[192];
    int length = snprintf(buffer, sizeof(buffer),
                          "runtime-symbol-trap-error operation=%s errno=%d\n",
                          operation, errno);
    if (length > 0) {
        write_all(STDERR_FILENO, buffer, (size_t)length);
    }
    _exit(CONTROL_EXIT);
}

static int valid_symbol(const char *symbol) {
    size_t length = strlen(symbol);
    if (length == 0 || length > MAX_SYMBOL_BYTES) {
        return 0;
    }
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)symbol[index];
        int valid = (byte >= 'A' && byte <= 'Z') ||
                    (byte >= 'a' && byte <= 'z') ||
                    (byte >= '0' && byte <= '9') || byte == '_';
        if (!valid || (index == 0 && byte >= '0' && byte <= '9')) {
            return 0;
        }
    }
    return 1;
}

static void trap_signal(int signal_number, siginfo_t *info, void *context) {
    (void)signal_number;
    (void)context;
    void *fault = info == NULL ? NULL : info->si_addr;
    for (size_t index = 0; index < trap_count; index++) {
        if (fault == traps[index].address) {
            write_all(marker_descriptor, traps[index].triggered_line,
                      traps[index].triggered_line_length);
            _exit(TRAP_EXIT);
        }
    }
    static const char unowned[] = "triggered=unowned-signal\n";
    write_all(marker_descriptor, unowned, sizeof(unowned) - 1);
    _exit(CONTROL_EXIT);
}

static void install_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = trap_signal;
    action.sa_flags = SA_SIGINFO;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGILL, &action, NULL) != 0 ||
        sigaction(SIGTRAP, &action, NULL) != 0) {
        fail("sigaction");
    }
}

static void make_writable(void *start, size_t length) {
    long raw_page_size = sysconf(_SC_PAGESIZE);
    if (raw_page_size <= 0) {
        fail("page-size");
    }
    uintptr_t page_size = (uintptr_t)raw_page_size;
    uintptr_t address = (uintptr_t)start;
    uintptr_t first = address & ~(page_size - 1);
    uintptr_t last = (address + length + page_size - 1) & ~(page_size - 1);
    size_t extent = (size_t)(last - first);
#if defined(__APPLE__)
    kern_return_t status = mach_vm_protect(
        mach_task_self(), (mach_vm_address_t)first, (mach_vm_size_t)extent,
        FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (status != KERN_SUCCESS) {
        errno = (int)status;
        fail("mach-vm-protect-rw-copy");
    }
#else
    if (mprotect((void *)first, extent, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fail("mprotect-rwx");
    }
#endif
}

static void make_executable(void *start, size_t length) {
    long raw_page_size = sysconf(_SC_PAGESIZE);
    if (raw_page_size <= 0) {
        fail("page-size-restore");
    }
    uintptr_t page_size = (uintptr_t)raw_page_size;
    uintptr_t address = (uintptr_t)start;
    uintptr_t first = address & ~(page_size - 1);
    uintptr_t last = (address + length + page_size - 1) & ~(page_size - 1);
    size_t extent = (size_t)(last - first);
#if defined(__APPLE__)
    kern_return_t status = mach_vm_protect(
        mach_task_self(), (mach_vm_address_t)first, (mach_vm_size_t)extent,
        FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (status != KERN_SUCCESS) {
        errno = (int)status;
        fail("mach-vm-protect-rx");
    }
#else
    if (mprotect((void *)first, extent, PROT_READ | PROT_EXEC) != 0) {
        fail("mprotect-rx");
    }
#endif
}

static void hex_bytes(char *output, const unsigned char *bytes, size_t length) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < length; index++) {
        output[index * 2] = digits[bytes[index] >> 4];
        output[index * 2 + 1] = digits[bytes[index] & 15];
    }
    output[length * 2] = '\0';
}

static void install_one(const char *symbol) {
    if (trap_count == MAX_TRAPS || !valid_symbol(symbol)) {
        fail("symbol-count-or-grammar");
    }
    for (size_t index = 0; index < trap_count; index++) {
        if (strcmp(traps[index].symbol, symbol) == 0) {
            fail("duplicate-symbol");
        }
    }
    void *address = dlsym(RTLD_DEFAULT, symbol);
    if (address == NULL) {
        fail("dlsym");
    }
    Dl_info image;
    if (dladdr(address, &image) == 0 || image.dli_fbase == NULL) {
        fail("dladdr");
    }
#if defined(__aarch64__)
    static const unsigned char replacement[] = {0x00, 0x00, 0x20, 0xd4};
    static const char architecture[] = "aarch64";
#elif defined(__x86_64__)
    static const unsigned char replacement[] = {0x0f, 0x0b};
    static const char architecture[] = "x86_64";
#else
#error unsupported qualification architecture
#endif
    unsigned char before[sizeof(replacement)];
    memcpy(before, address, sizeof(before));
    make_writable(address, sizeof(replacement));
    memcpy(address, replacement, sizeof(replacement));
    __builtin___clear_cache((char *)address, (char *)address + sizeof(replacement));
    make_executable(address, sizeof(replacement));
    char before_hex[sizeof(replacement) * 2 + 1];
    char after_hex[sizeof(replacement) * 2 + 1];
    hex_bytes(before_hex, before, sizeof(before));
    hex_bytes(after_hex, replacement, sizeof(replacement));
    uintptr_t offset = (uintptr_t)address - (uintptr_t)image.dli_fbase;
    char line[768];
    int length = snprintf(line, sizeof(line),
                          "armed=%s offset=0x%lx before=%s after=%s\n",
                          symbol, (unsigned long)offset, before_hex, after_hex);
    if (length <= 0 || (size_t)length >= sizeof(line)) {
        fail("marker-line");
    }
    write_all(marker_descriptor, line, (size_t)length);
    traps[trap_count].address = address;
    memcpy(traps[trap_count].symbol, symbol, strlen(symbol) + 1);
    length = snprintf(traps[trap_count].triggered_line,
                      sizeof(traps[trap_count].triggered_line),
                      "triggered=%s\n", symbol);
    if (length <= 0 || (size_t)length >= sizeof(traps[trap_count].triggered_line)) {
        fail("trigger-line");
    }
    traps[trap_count].triggered_line_length = (size_t)length;
    trap_count++;
    (void)architecture;
}

__attribute__((constructor)) static void install_runtime_symbol_traps(void) {
    const char *marker = getenv("FRE_AOT_CENSUS_TRAP_MARKER");
    const char *symbols = getenv("FRE_AOT_CENSUS_TRAP_SYMBOLS");
    const char *kind = getenv("FRE_AOT_CENSUS_TRAP_KIND");
    if (marker == NULL || symbols == NULL || symbols[0] == '\0' || kind == NULL) {
        fail("environment");
    }
    if (strcmp(kind, "semantic-helpers") != 0 &&
        strcmp(kind, "claimed-operation-entry") != 0) {
        fail("kind");
    }
    marker_descriptor = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (marker_descriptor < 0) {
        fail("marker-open");
    }
#if defined(__aarch64__)
    const char *architecture = "aarch64";
#elif defined(__x86_64__)
    const char *architecture = "x86_64";
#endif
    char header[512];
    int header_length = snprintf(
        header, sizeof(header), "schema=%s\nkind=%s\narchitecture=%s\n",
        "fre.aot-rebar.runtime-trap.v1", kind, architecture);
    if (header_length <= 0 || (size_t)header_length >= sizeof(header)) {
        fail("header");
    }
    write_all(marker_descriptor, header, (size_t)header_length);
    install_signal_handlers();
    char *copy = strdup(symbols);
    if (copy == NULL) {
        fail("strdup");
    }
    size_t expected = 0;
    char *save = NULL;
    for (char *symbol = strtok_r(copy, ",", &save); symbol != NULL;
         symbol = strtok_r(NULL, ",", &save)) {
        install_one(symbol);
        expected++;
    }
    free(copy);
    if (expected == 0 || expected != trap_count) {
        fail("installed-count");
    }
    char footer[96];
    int footer_length = snprintf(footer, sizeof(footer),
                                 "installed=%lu\nexpected=%lu\n",
                                 (unsigned long)trap_count,
                                 (unsigned long)expected);
    if (footer_length <= 0 || (size_t)footer_length >= sizeof(footer)) {
        fail("footer");
    }
    write_all(marker_descriptor, footer, (size_t)footer_length);
    if (fsync(marker_descriptor) != 0) {
        fail("marker-fsync");
    }
}

__attribute__((destructor)) static void complete_runtime_symbol_traps(void) {
    if (marker_descriptor >= 0) {
        static const char completed[] = "completed=normal\n";
        write_all(marker_descriptor, completed, sizeof(completed) - 1);
        (void)fsync(marker_descriptor);
        (void)close(marker_descriptor);
        marker_descriptor = -1;
    }
}
