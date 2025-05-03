// C wrapper for pimeshlogger
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    const char *python_path = "/bin/python3";
    const char *script_path = "/usr/local/src/pimeshlogger.py";

    char *cmd[argc + 3];
    cmd[0] = (char *)python_path;
    cmd[1] = (char *)script_path;
    for (int i = 1; i < argc; i++) {
        cmd[i + 1] = argv[i];
    }
    cmd[argc + 1] = NULL;

    execvp(python_path, cmd);
    perror("execvp failed");
    return 1;
}

