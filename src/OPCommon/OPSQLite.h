#include <string>
#include <sqlite3.h>
#include "../lib/json.hpp"
#define OPS
using namespace std;
using json = nlohmann::json;

enum XPCSelectType
{
    client_pid,
    service_name
};
enum HookingPIDType
{
    Tracee,
    Tracer
};

struct ProcLogSql{
    string event;
    string pid;
    string euid;
    string rpid;
    string path;
    string args;
    string time;
};

class OPSQLite
{
public:
    OPSQLite();
    ~OPSQLite();
    bool CreateTable();
    bool InsertHooking(pid_t tracer, pid_t tracee);
    bool SearchHookingIfExist(pid_t target_pid, HookingPIDType type);
    bool RemoveHooking(pid_t target_pid, HookingPIDType type);
    bool InsertXPC(pid_t client_pid, string xpc_name);
    bool SearchXPCIfExist(string xpc_name, string& matched_pid);
    bool InsertProcLog(const ProcLogSql proc);
    ProcLogSql DumpProcLog(pid_t target_pid);
private:
    bool query(const string &sql_query);
    bool query_select(const string &sql_query, json* res);
    

    sqlite3 *db_;
    const string path_ = "./.onPrivilege.sqlite";
};
