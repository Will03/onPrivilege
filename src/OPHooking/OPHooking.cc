
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <array>
#include <iostream>
#include <regex>
#include <string>

#include "../OPCommon/OPLogger.h"
#include "../OPCommon/OPSQLite.h"

using namespace std;
int main(int argc, const char *argv[]) {
    OPSQLite sql;
    if (argc != 2) {
        return 0;
    }
    string tracee_pid = string(argv[1]);

    string cmd = "unbuffer ./XPoCe " + tracee_pid + " 2>&1";

    // waitting a little for process initialize
    usleep(100000);

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        cerr << "Couldn't start command." << std::endl;
        return 0;
    }
    array<char, 65536> buffer;
    char buf[65536];

    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    int d = fileno(pipe);
    regex xpc_reg("xpc_connection_create_mach_service \\( \"(([.\\w])+)\"");

    int read_size;
    while (1) {
        read_size = read(d, buf, 65536);
        // cout << read_size << endl;
        if (read_size) {
            smatch sm;
            string test = buf;
            // cout << test << endl;
            while (regex_search(test, sm, xpc_reg)) {
                if (sm.size() > 0) {
                    OPLogger::GetInstance().INFO(tracee_pid +
                                                 " XPC Create: " + sm[1].str());

                    sql.InsertXPC(stoi(tracee_pid), sm[1].str());
                }
                test = sm.suffix();
            }
            if (test.find("Exiting") != string::npos) {
                string kill_cmd =
                    string("ps aux | grep -ie \"") + cmd +
                    string(
                        "\" | grep -v grep | awk '{print $2}' | xargs kill -9");
                // cout << kill_cmd << endl;
                system(kill_cmd.c_str());
                break;
            }
        }
    }
    string test;
    sql.RemoveHooking(getpid(), HookingPIDType::Tracer);

    pclose(pipe);
}