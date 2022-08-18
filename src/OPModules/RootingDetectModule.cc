#include "RootingDetectModule.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <string>

#include "../OPCommon/OPLogger.h"

using namespace std;

void RootingDetectModule::OnCreate(const es_event_create_t *event) {
    OPModule::OnCreate(event);
    string result_pid;
    OPSQLite sql;

    if (event_.process_euid == 0 &&
        OPUtils::IsProtectedDirectory(event_.parameters["file_dir"])) {
        // Is malicious behavior
        if (sql.SearchXPCIfExist(event_.process_signing_id, result_pid)) {
            OPLogger::GetInstance().INFO("Find privilege attack: " +
                                         event_.parameters["file_dir"]);
            // OPUtils::PopAlertMessage("onPrivilege Message","Process Rooting
            // Detect");

            GenRootingReport(
                stoi(result_pid), event_.process_signing_id,
                "Process used XPC service to access protected file or "
                "folder.\nFile path: " +
                    event_.parameters["file_dir"] + "\n");
        }
    }
}

void RootingDetectModule::OnExec(const es_event_exec_t *event) {
    OPModule::OnExec(event);
}

bool RootingDetectModule::event_callback(const Event &event) {
    // OutputProc(event);
}

void RootingDetectModule::ModuleStart() {
    std::vector<es_event_type_t> subscriptions;
    subscriptions.clear();
    for (auto each_event : NOTIFYEVENTS) {
        subscriptions.push_back(each_event.second);
    }
    CreateClient(event_callback);
    SubscribeClient(subscriptions);

    while (true) {
        sleep(10);
    }
    pause();
}
