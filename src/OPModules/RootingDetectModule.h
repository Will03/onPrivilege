#include <EndpointSecurity/EndpointSecurity.h>

#include <iostream>
#include <map>
#include <string>

#ifndef OPM
#include "OPModule.h"
#endif
using namespace std;

class RootingDetectModule : OPModule {
    std::map<string, es_event_type_t> NOTIFYEVENTS = {
        {"exec", ES_EVENT_TYPE_NOTIFY_EXEC},
        {"create", ES_EVENT_TYPE_NOTIFY_CREATE}};

   public:
    void ModuleStart() override;
    static bool event_callback(const Event &event);
    void OnExec(const es_event_exec_t *event) override;
    void OnCreate(const es_event_create_t *event) override;
};