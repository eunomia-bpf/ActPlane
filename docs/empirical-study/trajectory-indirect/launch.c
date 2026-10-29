// Mark the replay dispatcher, then exec its command. The observer excludes that
// first dispatcher exec and attributes its descendants to this recorded call.
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3 || strncmp(argv[1], "apti6e", 6) || strlen(argv[1]) > 15) return 2;
    if (prctl(PR_SET_NAME, argv[1], 0, 0, 0)) { perror("prctl"); return 3; }
    struct rlimit cores = {0, 0};
    setrlimit(RLIMIT_CORE, &cores);
    execvp(argv[2], argv + 2);
    perror("execvp");
    return 127;
}
