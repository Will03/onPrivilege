#include "OPSQLite.h"

#include <sqlite3.h>
#include <unistd.h>

#include <iostream>

#include "../OPCommon/OPLogger.h"
#include "../lib/json.hpp"

using namespace std;

OPSQLite::~OPSQLite() { sqlite3_close(db_); }

OPSQLite::OPSQLite() {
    int rc;
    rc = sqlite3_open(path_.c_str(), &db_);

    if (rc) {
        // throw_exception("Can't open database: %s\n", sqlite3_errmsg(db_));
        OPLogger::GetInstance().DEBUG("db init fail");
    }
}
bool OPSQLite::query_select(const string &sql_query, json *res) {
    // std::lock_guard<std::recursive_mutex> lock(mutex_);
    char *zErrMsg = 0;

    auto extractJson = [](void *data, int argc, char **argv, char **azColName) {
        json &res = *(json *)data;
        json obj = json::object();
        for (int i = 0; i < argc; i++) {
            obj[azColName[i]] = string(argv[i] ? argv[i] : "NULL");
        }
        res.push_back(obj);
        return 0;
    };

    int rc = sqlite3_exec(db_, sql_query.c_str(), extractJson, (json *)res,
                          &zErrMsg);
    if (rc != SQLITE_OK) {
        // throw_exception("SQL error: %s\n", zErrMsg);
        // OPLogger::GetInstance().DEBUG("SQL error: "+ sql_query);
        sqlite3_free(zErrMsg);
        return false;
    }
    return true;
}
bool OPSQLite::SearchXPCIfExist(string xpc_name, string &matched_pid) {
    string xpc_pair_sql = "SELECT * FROM XPC";

    json res;
    while (!query_select(xpc_pair_sql, &res)) {
        usleep(300000);
    }
    // OPLogger::GetInstance().DEBUG(res.dump());
    // OPLogger::GetInstance().DEBUG("===========XPC=============");
    for (auto &each : res) {
        if (each.empty() || !each.contains("xpc_client_pid") ||
            !each.contains("xpc_service_name"))
            continue;

        string pid = each.value("xpc_client_pid", "Error");
        string name = each.value("xpc_service_name", "Error");
        if (name.find(xpc_name) != string::npos) {
            matched_pid = pid;
            return true;
        }
    }
    return false;
}

bool OPSQLite::SearchHookingIfExist(pid_t target_pid, HookingPIDType type) {
    string hooking_pair_sql = "SELECT ";
    if (type == HookingPIDType::Tracee)
        hooking_pair_sql += "tracer_pid FROM HOOKPID";
    else if (type == HookingPIDType::Tracer)
        hooking_pair_sql += "tracer_pid FROM HOOKPID";
    else
        return false;
    json res;
    query_select(hooking_pair_sql, &res);

    // OPLogger::GetInstance().DEBUG(res.dump());
    // OPLogger::GetInstance().DEBUG("=========================");
    for (auto &a : res) {
        if (a.empty() || !a.contains("tracer_pid")) continue;

        string pid = a.value("tracer_pid", "Error");
        // cout << pid;
        if (pid.compare(to_string(target_pid)) == 0) {
            return true;
        }
    }
    return false;
}

ProcLogSql OPSQLite::DumpProcLog(pid_t target_pid) {
    string proc_pair_sql = "SELECT * FROM PROCLOG";
    ProcLogSql proc_log;
    json res;
    query_select(proc_pair_sql, &res);

    // OPLogger::GetInstance().DEBUG(res.dump());
    // OPLogger::GetInstance().DEBUG("=========================");

    for (auto &each : res) {
        if (each.empty() || !each.contains("event")) continue;
        if (each.value("event", "error") != "exec") continue;
        if (each.value("pid", "error") != to_string(target_pid)) {
            continue;
        }
        proc_log.pid = each.value("pid", "error");
        proc_log.args = each.value("args", "error");
        proc_log.euid = each.value("euid", "error");
        proc_log.event = each.value("event", "error");
        proc_log.path = each.value("path", "error");
        proc_log.rpid = each.value("rpid", "error");
        proc_log.time = each.value("time", "error");
        return proc_log;
    }
    return proc_log;
}

bool OPSQLite::InsertXPC(pid_t client_pid, string xpc_name) {
    string xpc_pair_sql = "INSERT INTO XPC VALUES ( \"";
    xpc_pair_sql += to_string(client_pid) + "\" ,\"" + xpc_name + "\" )";
    // OPLogger::GetInstance().DEBUG("xpc query: " + xpc_pair_sql);
    query(xpc_pair_sql);
    return true;
}

bool OPSQLite::InsertHooking(pid_t tracer, pid_t tracee) {
    string hooking_pair_sql = "INSERT INTO HOOKPID VALUES ( ";
    hooking_pair_sql += to_string(tracer) + "," + to_string(tracee) + " )";

    query(hooking_pair_sql);
    return true;
}

bool OPSQLite::InsertProcLog(const ProcLogSql proc) {
    string proc_log_sql = "INSERT INTO PROCLOG VALUES ( \"" + proc.event +
                          "\",\"" + proc.pid + "\",\"" + proc.euid + "\",\"" +
                          proc.rpid + "\",\"" + proc.path + "\",\"" +
                          proc.args + "\",\"" + proc.time + "\")";
    // query(hook_sql);

    query(proc_log_sql);
    return true;
}

bool OPSQLite::query(const string &sql_query) {
    if (SQLITE_OK != sqlite3_exec(db_, sql_query.c_str(), NULL, NULL, NULL)) {
        // OPLogger::GetInstance().DEBUG("db sql error");
        return false;
    }
    return true;
}

bool OPSQLite::CreateTable() {
    const string hooking_pid_sql =
        "CREATE TABLE HOOKPID("
        "tracer_pid          varchar(10)     NOT NULL,"
        "tracee_pid            varchar(10)      NOT NULL);";
    const string xpc_connection_sql =
        "CREATE TABLE XPC("
        "xpc_client_pid          varchar(20)     NOT NULL,"
        "xpc_service_name            varchar(20)      NOT NULL);";

    const string process_log_sql =
        "CREATE TABLE PROCLOG("
        "event          varchar(20)     NOT NULL,"
        "pid            varchar(20)      NOT NULL,"
        "euid            varchar(20)      NOT NULL,"
        "rpid            varchar(20)      NOT NULL,"
        "path            varchar(20)      NOT NULL,"
        "args            varchar(100)      NOT NULL,"
        "time            varchar(50)      NOT NULL)";

    const string app_version_sql =
        "CREATE TABLE APPVERSION("
        "app_name          varchar(20)     NOT NULL,"
        "version            varchar(20)      NOT NULL);";

    query(hooking_pid_sql);
    query(xpc_connection_sql);
    query(process_log_sql);
    query(app_version_sql);
    return true;
}

bool OPSQLite::RemoveHooking(pid_t target_pid, HookingPIDType type) {
    string hooking_pair_sql = "DELETE FROM HOOKPID WHERE ";
    if (type == HookingPIDType::Tracee)
        hooking_pair_sql += "tracee_pid='" + to_string(target_pid) + "'";
    else if (type == HookingPIDType::Tracer)
        hooking_pair_sql += "tracer_pid='" + to_string(target_pid) + "'";
    else
        return false;
    query(hooking_pair_sql);
    return true;
}
