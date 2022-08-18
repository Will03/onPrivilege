#include "TCCBypassDetectModule.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <string>

#include "../OPCommon/OPLogger.h"

using namespace std;

void TCCBypassDetectModule::OnReadlink(const es_event_readlink_t *event) {
    OPModule::OnReadlink(event);
    event_.event = "readlink";
    event_.parameters["file_name"] = OPUtils::EsFileToStr(event->source);
    OPLogger::GetInstance().DEBUG(event_.parameters["file_name"]);
    if (OPUtils::IsIncludeTCCDirectory(event_.parameters["file_name"])) {
        GenTCCReport(event_, "Process try to read tcc database");
    }
}
void TCCBypassDetectModule::OnMount(const es_event_mount_t *event) {
    OPModule::OnMount(event);
    event_.event = "mount";
    event_.parameters["f_mntfromname"] = event->statfs->f_mntfromname;
    event_.parameters["f_mntonname"] = event->statfs->f_mntonname;
    OPLogger::GetInstance().DEBUG(event_.parameters["f_mntonname"] + "  " +
                                  event_.parameters["f_mntfromname"]);
}

void TCCBypassDetectModule::OnReaddir(const es_event_readdir_t *event) {
    OPModule::OnReaddir(event);
    if (OPUtils::IsIncludeTCCDirectory(event_.parameters["file_path"])) {
        GenTCCReport(event_, "Process try to read tcc database");
    }
}

bool TCCBypassDetectModule::event_callback(const Event &event) {
    // OutputProc(event);
}

void TCCBypassDetectModule::GenTCCReport(const Event &event,
                                         string cause_message) {
    ProcLogSql proc_info = {event.event,
                            to_string(event.process_pid),
                            to_string(event.process_euid),
                            to_string(event.process_rpid),
                            event.process_executable,
                            event.process_arguments,
                            event.timestamp};
    string print_report = "-----------------------\n";
    print_report += "Malicious Behavior:\n    " + cause_message;
    print_report += "\nProcess Info:\n" + GenProcessInfo(proc_info);
    print_report += "-----------------------";
    GenReport(proc_info.pid + "_tcc", print_report);
}

void TCCBypassDetectModule::ModuleStart() {
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
