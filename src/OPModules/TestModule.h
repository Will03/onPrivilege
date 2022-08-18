#include <EndpointSecurity/EndpointSecurity.h>

#include <iostream>
#include <map>
#include <string>
#ifndef OPM
#include "OPModule.h"
#endif
using namespace std;

class TestModule : OPModule {
    std::map<string, es_event_type_t> NOTIFYEVENTS = {
        {"access", ES_EVENT_TYPE_NOTIFY_ACCESS},
        {"open", ES_EVENT_TYPE_NOTIFY_OPEN},
        {"read", ES_EVENT_TYPE_NOTIFY_READLINK},
        {"write", ES_EVENT_TYPE_NOTIFY_WRITE},
        {"exec", ES_EVENT_TYPE_NOTIFY_EXEC}};

   public:
    void ModuleStart() override;
    static bool event_callback(const Event &event);
};