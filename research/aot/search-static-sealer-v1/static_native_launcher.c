#define _POSIX_C_SOURCE 200809L

#include <Python.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

static void reject_ambient_injection(void) {
    for (char **entry = environ; *entry != NULL; ++entry) {
        if (strncmp(*entry, "PYTHON", 6) == 0 ||
            strncmp(*entry, "LD_", 3) == 0 ||
            strncmp(*entry, "DYLD_", 5) == 0) {
            const char *separator = strchr(*entry, '=');
            int length = separator == NULL
                ? (int)strlen(*entry)
                : (int)(separator - *entry);
            fprintf(
                stderr,
                "fre-static-native-launcher: ambient injection: %.*s\n",
                length,
                *entry
            );
            exit(127);
        }
    }
}

static void stop_for_kernel_attestation(const char *launcher_path) {
    const char *encoded = getenv("FRE_STATIC_ATTEST_MONITOR_FD");
    if (encoded == NULL || encoded[0] == '\0') {
        fputs("fre-static-native-launcher: missing monitor fd\n", stderr);
        exit(127);
    }
    char *end = NULL;
    long parsed = strtol(encoded, &end, 10);
    if (end == encoded || *end != '\0' || parsed < 3 || parsed > 1048576) {
        fputs("fre-static-native-launcher: malformed monitor fd\n", stderr);
        exit(127);
    }
    if (strchr(launcher_path, '\n') != NULL ||
        strchr(launcher_path, '\r') != NULL ||
        strlen(launcher_path) > 255U) {
        fputs("fre-static-native-launcher: unsafe launcher path\n", stderr);
        exit(127);
    }
    int descriptor = (int)parsed;
    int written = dprintf(
        descriptor,
        "FRELAUNCH1 %ld %ld %s\n",
        (long)getpid(),
        (long)getppid(),
        launcher_path
    );
    if (written <= 0 || written > 511) {
        fputs("fre-static-native-launcher: monitor write failed\n", stderr);
        exit(127);
    }
    if (raise(SIGSTOP) != 0) {
        fputs("fre-static-native-launcher: attestation stop failed\n", stderr);
        exit(127);
    }
}

static int run_held_wrapper(
    int argc,
    char **argv,
    const char *wrapper
) {
    int descriptor = open(wrapper, O_RDONLY | O_CLOEXEC);
    struct stat wrapper_status;
    if (descriptor < 0 || fstat(descriptor, &wrapper_status) != 0 ||
        !S_ISREG(wrapper_status.st_mode) ||
        wrapper_status.st_size <= 0 ||
        wrapper_status.st_size > 4 * 1024 * 1024) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        fputs(
            "fre-static-native-launcher: invalid held wrapper\n",
            stderr
        );
        return 127;
    }
    size_t source_bytes = (size_t)wrapper_status.st_size;
    char *source = calloc(source_bytes + 1U, sizeof(*source));
    if (source == NULL) {
        close(descriptor);
        fputs("fre-static-native-launcher: allocation failed\n", stderr);
        return 127;
    }
    size_t offset = 0;
    while (offset < source_bytes) {
        ssize_t count = pread(
            descriptor,
            source + offset,
            source_bytes - offset,
            (off_t)offset
        );
        if (count <= 0) {
            free(source);
            close(descriptor);
            fputs(
                "fre-static-native-launcher: held wrapper read failed\n",
                stderr
            );
            return 127;
        }
        offset += (size_t)count;
    }
    close(descriptor);
    if (memchr(source, '\0', source_bytes) != NULL) {
        free(source);
        fputs(
            "fre-static-native-launcher: held wrapper contains NUL\n",
            stderr
        );
        return 127;
    }
    size_t count = (size_t)argc + 2U;
    if (count < (size_t)argc) {
        free(source);
        fputs("fre-static-native-launcher: argv overflow\n", stderr);
        return 127;
    }
    char **python_argv = calloc(count, sizeof(*python_argv));
    if (python_argv == NULL) {
        free(source);
        fputs("fre-static-native-launcher: allocation failed\n", stderr);
        return 127;
    }
    python_argv[0] = (char *)wrapper;
    for (int index = 0; index < argc; ++index) {
        python_argv[(size_t)index + 1U] = argv[index];
    }
    python_argv[(size_t)argc + 1U] = NULL;

    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.isolated = 1;
    config.use_environment = 0;
    config.user_site_directory = 0;
    config.site_import = 0;
    config.write_bytecode = 0;
    config.parse_argv = 0;
    PyStatus status = PyConfig_SetBytesString(
        &config,
        &config.program_name,
        argv[0]
    );
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetBytesArgv(
            &config,
            argc + 1,
            python_argv
        );
    }
    if (!PyStatus_Exception(status)) {
        status = Py_InitializeFromConfig(&config);
    }
    free(python_argv);
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        free(source);
        Py_ExitStatusException(status);
    }
    PyConfig_Clear(&config);
    PyObject *main_module = PyImport_AddModule("__main__");
    PyObject *globals = main_module == NULL
        ? NULL
        : PyModule_GetDict(main_module);
    PyObject *filename = PyUnicode_DecodeFSDefault(wrapper);
    int result = 127;
    if (globals != NULL && filename != NULL &&
        PyDict_SetItemString(globals, "__file__", filename) == 0) {
        PyObject *value = PyRun_StringFlags(
            source,
            Py_file_input,
            globals,
            globals,
            NULL
        );
        if (value != NULL) {
            Py_DECREF(value);
            result = 0;
        } else if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
            PyObject *type = NULL;
            PyObject *exception = NULL;
            PyObject *traceback = NULL;
            PyErr_Fetch(&type, &exception, &traceback);
            PyErr_NormalizeException(&type, &exception, &traceback);
            PyObject *code = exception == NULL
                ? NULL
                : PyObject_GetAttrString(exception, "code");
            if (code == Py_None) {
                result = 0;
            } else if (code != NULL && PyLong_Check(code)) {
                long encoded = PyLong_AsLong(code);
                if (!PyErr_Occurred() &&
                    encoded >= 0 && encoded <= UCHAR_MAX) {
                    result = (int)encoded;
                }
            }
            Py_XDECREF(code);
            Py_XDECREF(type);
            Py_XDECREF(exception);
            Py_XDECREF(traceback);
            PyErr_Clear();
        } else {
            PyErr_Print();
        }
    } else {
        PyErr_Print();
    }
    Py_XDECREF(filename);
    free(source);
    if (Py_FinalizeEx() < 0 && result == 0) {
        result = 127;
    }
    return result;
}

int main(int argc, char **argv) {
    if (argc < 1 || argv == NULL || argv[0] == NULL || argv[0][0] == '\0') {
        fputs("fre-static-native-launcher: malformed argv\n", stderr);
        return 127;
    }
    reject_ambient_injection();
    stop_for_kernel_attestation(argv[0]);
    const char *wrapper = getenv("FRE_STATIC_ATTEST_WRAPPER_SCRIPT_PATH");
    if (wrapper == NULL || wrapper[0] != '/') {
        fputs(
            "fre-static-native-launcher: missing absolute wrapper script\n",
            stderr
        );
        return 127;
    }
    return run_held_wrapper(argc, argv, wrapper);
}
