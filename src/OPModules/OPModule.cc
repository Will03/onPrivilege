#include "OPModule.h"

#include <bsm/libbsm.h>
#include <spawn.h>
#include <unistd.h>

#include "../OPCommon/OPLogger.h"
#include "../OPCommon/utils.h"
#define CS_VALID 0x00000001
extern char **environ;
OPModule::OPModule() {}

OPModule::~OPModule() {}

bool OPModule::CreateClient(std::function<int(const Event &)> callback_func) {

    es_new_client_result_t ret = es_new_client(
        &client_, ^(es_client_t *client, const es_message_t *message) {
          EventHandle(message);
        });

    switch (ret) {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            OPLogger::GetInstance().ERROR(
                "ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            OPLogger::GetInstance().ERROR(
                "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            OPLogger::GetInstance().ERROR(
                "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            OPLogger::GetInstance().ERROR(
                "ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            OPLogger::GetInstance().ERROR(
                "ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            OPLogger::GetInstance().ERROR("ES_NEW_CLIENT_RESULT_ERR_INTERNAL");
            break;

        default:
            OPLogger::GetInstance().ERROR("Unknown error");
            break;
    }
    // For mute process
    // es_return_t res = es_mute_path_literal(client_, XPoCe_path.c_str());

    // if (res != ES_RETURN_SUCCESS){
    //     OPLogger::GetInstance().ERROR("mute failed: %@");
    // }

    callback_func_ = callback_func;
}

bool OPModule::DeleteClient() {}

void OPModule::SubscribeClient(const std::vector<es_event_type_t> &events) {
    if (!client_) {
        OPLogger::GetInstance().ERROR("no init client");
        return;
    }

    es_return_t res = es_subscribe(client_, events.data(), events.size());

    if (res == ES_RETURN_ERROR) {
        OPLogger::GetInstance().ERROR("es_subscribe fail");
        return;
    }
}

void OPModule::OutputProc(const Event &event) {
    cout << "event: " << event.event << "\n"
         << "\ttime: " << event.timestamp << "\n";

    for (auto k : event.parameters) {
        cout << "\t" << k.first << ": " << k.second << "\n";
    }
    cout << " process:\n"
         << "        PID : " << event.process_pid << "\n"
         << "       EUID : " << event.process_euid
         << "\n"
         //         << "       EGID : " << event.process_egid << "\n"
         << "       PPID : " << event.process_ppid << "\n";

    cout << "        GID : " << event.process_gid << "\n"
         << "        SID : " << event.process_sid << "\n"
         << "   threadid : " << event.process_sid << "\n"
         << "       RPID : " << event.process_rpid << "\n"
         << "       path : " << event.process_executable << "\n"
         << "       ARGS : " << event.process_arguments << "\n";
    //        << "    sign_id : " << event.process_signing_id << "\n"
    //        << "    started : " << event.process_start_time << "\n"
    //        << "      extra : " << (event.process_is_platform_binary ?
    //        "(platform_binary) " : "")
    // << (event.process_is_es_client ? "(es_client) " : "") << "\n";
    cout << "    cs_flag : 0x" << std::hex << (event.process_csflags)
         << std::dec << "\n";

    if (!event.process_team_id.empty())
        std::cout << "    team_id : " << event.process_team_id << "\n";
}

void OPModule::EventHandle(const es_message_t *message) {
    pid_t pid = audit_token_to_pid(message->process->audit_token);
    if (message->process->is_es_client == true || pid == getpid()) {
        return;
    }
    event_.parameters.clear();
    event_.timestamp = OPUtils::TimespecToString(message->time.tv_sec) + "." +
                       std::to_string(message->time.tv_nsec);
    event_.is_authentication = (message->action_type == ES_ACTION_TYPE_AUTH);
    event_.process_pid = pid;
    event_.process_euid = audit_token_to_euid(message->process->audit_token);
    event_.process_ruid = audit_token_to_ruid(message->process->audit_token);
    event_.process_rgid = audit_token_to_rgid(message->process->audit_token);
    event_.process_egid = audit_token_to_egid(message->process->audit_token);
    event_.process_ppid = message->process->ppid;
    event_.process_oppid = message->process->original_ppid;
    event_.process_gid = message->process->group_id;
    event_.process_sid = message->process->session_id;
    // event_.process_rpid =
    // audit_token_to_pid(message->process->responsible_audit_token);
    event_.process_rpid = -1;

    event_.process_csflags = message->process->codesigning_flags;
    // event_.process_csflags_desc = EndpointSecurityImpl::getBitmask(
    // value_map_codesign, message->process->codesigning_flags );
    event_.process_is_platform_binary = message->process->is_platform_binary;
    event_.process_is_es_client = message->process->is_es_client;
    event_.process_thread_id = -1;
    event_.process_signing_id =
        OPUtils::EsStringTokenToStr(message->process->signing_id);
    event_.process_team_id =
        OPUtils::EsStringTokenToStr(message->process->team_id);
    event_.process_executable =
        OPUtils::EsFileToStr(message->process->executable);

    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            OnAccess(message->event.access.target, message->event.access.mode);
            break;
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            OnOpen(message->event.open.file, message->event.open.fflag);
            break;
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            OnReadlink(&message->event.readlink);
            break;
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            OnWrite(message->event.write.target);
            break;
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            OnExec(&message->event.exec);
            break;
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            OnCreate(&message->event.create);
            break;
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            OnMount(&message->event.mount);
            break;
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            OnReaddir(&message->event.readdir);
            break;
    }

    LogProcInfo();

    callback_func_(event_);
}

void OPModule::CreateHooker(const pid_t tracee_pid) {
    pid_t new_pid;
    OPSQLite sql;
    char *my_argv[] = {"OPHooker", NULL, NULL};
    char pid_arr[10];
    sprintf(pid_arr, "%d", tracee_pid);
    my_argv[1] = pid_arr;

    int status;

    // hooking user process and csflag ==0
    if (event_.process_euid == 1 || event_.parameters["csflags"] != "0") {
        return;
    }

    OPLogger::GetInstance().INFO("start spawning");

    status = posix_spawn(&new_pid, "./OPHooker", NULL, NULL, my_argv, environ);
    sql.InsertHooking(new_pid, tracee_pid);
}

void OPModule::OnAccess(const es_file_t *target, int32_t mode) {
    event_.event = "access";
}
void OPModule::OnExec(const es_event_exec_t *event) {
    event_.event = "exec";
    event_.parameters["file_name"] =
        OPUtils::EsFileToStr(event->target->executable);
    event_.parameters["csflags"] = to_string(event->target->codesigning_flags);

    int arg_count = es_exec_arg_count(event);
    string args;
    for (uint32_t i = 0; i < arg_count; i++) {
        args += OPUtils::EsStringTokenToStr(es_exec_arg(event, i)) + " ";
    }
    event_.process_arguments = args;

    // we shouldn't hook our process.
    if (args.find("XPoCe") != string::npos ||
        args.find("OPHooker") != string::npos) {
        return;
    }
    CreateHooker(event_.process_pid);
}
void OPModule::OnOpen(const es_file_t *filename, int32_t fflag) {
    event_.event = "open";
}
void OPModule::OnWrite(const es_file_t *target) { event_.event = "write"; }
void OPModule::OnReadlink(const es_event_readlink_t *event) {
    event_.event = "readlink";
    event_.parameters["file_name"] = OPUtils::EsFileToStr(event->source);
}
void OPModule::OnMount(const es_event_mount_t *event) {
    event_.event = "mount";
    event_.parameters["f_mntfromname"] = event->statfs->f_mntfromname;
    event_.parameters["f_mntonname"] = event->statfs->f_mntonname;
}
void OPModule::OnCreate(const es_event_create_t *event) {
    event_.event = "create";
    event_.parameters["file_dir"] =
        OPUtils::EsFileToStr(event->destination.new_path.dir);
    event_.parameters["file_name"] =
        OPUtils::EsStringTokenToStr(event->destination.new_path.filename);
}
void OPModule::OnReaddir(const es_event_readdir_t *event) {
    event_.event = "readdir";
    event_.parameters["file_path"] =
        OPUtils::EsStringTokenToStr(event->target->path);
}

string OPModule::GenProcessInfo(ProcLogSql proc_info) {
    string res;
    res += "   pid  : " + proc_info.pid + "\n";
    res += "   euid : " + proc_info.euid + "\n";
    res += "   path : " + proc_info.path + "\n";
    res += "   args : " + proc_info.args + "\n";
    res += "   event: " + proc_info.event + "\n";
    res += "   time : " + proc_info.time + "\n";
    return res;
}

void OPModule::GenRootingReport(pid_t program_pid, string xpc_name,
                                string message) {
    OPLogger::GetInstance().INFO(program_pid + " " + xpc_name + " " + message);
    OPSQLite sql;
    ProcLogSql target_proc_info = sql.DumpProcLog(program_pid);
    string print_report = "-----------------------\n";
    print_report += "Malicious Behavior:\n    " + message;
    print_report += "\nProcess Info:\n" + GenProcessInfo(target_proc_info);
    print_report += "\nAbused XPC name:\n    " + xpc_name + "\n";
    print_report += "\n-----------------------";
    GenReport(to_string(program_pid) + "_rooting", print_report);
}

void OPModule::GenReport(string filename, string content) {
    OPLogger::GetInstance().INFO(content);
    string report_name = "./report/incident_" + filename + ".txt";
    OPUtils::op_write(report_name, content);
}

void OPModule::LogProcInfo() {
    OPSQLite sql;

    // Identify our module process
    if (event_.process_arguments.find("XPoCe") != string::npos ||
        event_.process_arguments.find("OPHooker") != string::npos) {
        return;
    }
    struct ProcLogSql proc_log_sql;
    proc_log_sql.args = event_.process_arguments;
    proc_log_sql.euid = to_string(event_.process_euid);
    proc_log_sql.event = event_.event;
    proc_log_sql.path = event_.process_executable;
    proc_log_sql.pid = to_string(event_.process_pid);
    proc_log_sql.rpid = to_string(event_.process_rpid);
    proc_log_sql.time = event_.timestamp;
    sql.InsertProcLog(proc_log_sql);
}