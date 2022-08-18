#include <EndpointSecurity/EndpointSecurity.h>

#include <iostream>
#include <map>
#include <string>

#ifndef OPM
#include "OPModule.h"
#endif
using namespace std;

class BypassGKModule : OPModule {
    std::map<string, es_event_type_t> NOTIFYEVENTS = {
        {"delete_attr", ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR}};

   public:
    void ModuleStart() override;
    static bool event_callback(const Event &event);
};