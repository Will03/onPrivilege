#include <EndpointSecurity/EndpointSecurity.h>

#include <iostream>
#include <map>
#include <string>

#ifndef OPM
#include "OPModule.h"
#endif
using namespace std;

class TCCBypassDetectModule : OPModule {
    std::map<string, es_event_type_t> NOTIFYEVENTS = {
        // {"exec", ES_EVENT_TYPE_NOTIFY_EXEC},
        {"mount", ES_EVENT_TYPE_NOTIFY_MOUNT},
        {"readdir", ES_EVENT_TYPE_NOTIFY_READDIR},
        // {"write", ES_EVENT_TYPE_NOTIFY_WRITE},
        {"get_task", ES_EVENT_TYPE_NOTIFY_GET_TASK},
        // {"get_task_name", ES_EVENT_TYPE_NOTIFY_GET_TASK_READ},
        // {"get_task_inspect", ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT}
    };

   public:
    void ModuleStart() override;
    static bool event_callback(const Event &event);
    void OnReadlink(const es_event_readlink_t *event) override;
    void OnReaddir(const es_event_readdir_t *event) override;
    void OnMount(const es_event_mount_t *event) override;
    void GenTCCReport(const Event &event, string cause_message);
};