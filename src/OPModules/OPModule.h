#include <functional>
#include <map>
#include <string>
#include <variant>
#include <vector>

#include "../OPCommon/OPSQLite.h"
#include "../OPCommon/utils.h"

#define OPM

#include <EndpointSecurity/EndpointSecurity.h>

using namespace std;

class OPModule {
   public:
    typedef struct event {
        std::string event;

        bool is_authentication;

        std::string timestamp;

        pid_t process_pid;
        pid_t process_euid;
        pid_t process_ruid;
        pid_t process_rgid;
        pid_t process_egid;
        pid_t process_ppid;
        pid_t process_oppid;
        pid_t process_gid;
        pid_t process_sid;
        pid_t process_rpid;
        uint32_t process_csflags;
        std::string process_csflags_desc;
        bool process_is_platform_binary;
        bool process_is_es_client;
        std::string process_signing_id;
        std::string process_team_id;
        uint64_t process_thread_id;
        std::string process_start_time;
        std::string process_executable;
        std::string process_arguments;
        std::map<std::string, std::string> parameters;
    } Event;

    OPModule();
    ~OPModule();

    bool CreateClient(std::function<int(const Event &)> callback_func);
    bool DeleteClient();

    void SubscribeClient(const std::vector<es_event_type_t> &events);
    void Unsubscribe(const std::vector<es_event_type_t> &events);
    void CreateHooker(const pid_t tracee_pid);
    void DetectHighPrivilege();
    void LogProcInfo();
    void GenRootingReport(pid_t program_pid, string xpc_name, string message);
    void GenReport(string filename, string content);
    string GenProcessInfo(ProcLogSql proc_info);

    static void OutputProc(const Event &event);

   protected:
    virtual void ModuleStart() = 0;
    virtual void EventHandle(const es_message_t *message);
    virtual void OnAccess(const es_file_t *target, int32_t mode);
    virtual void OnExec(const es_event_exec_t *event);
    virtual void OnOpen(const es_file_t *filename, int32_t fflag);
    virtual void OnWrite(const es_file_t *target);
    virtual void OnCreate(const es_event_create_t *event);
    virtual void OnReadlink(const es_event_readlink_t *event);
    virtual void OnMount(const es_event_mount_t *event);
    virtual void OnReaddir(const es_event_readdir_t *event);
    OPModule::Event event_;

   private:
    es_client_t *client_;
    function<int(const OPModule::Event &)> callback_func_;
};