#include "BypassGKModule.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <string>

#include "../OPCommon/OPLogger.h"
using namespace std;

bool BypassGKModule::event_callback(const Event &event) {
    OutputProc(event);
}

void BypassGKModule::ModuleStart() {
    std::vector<es_event_type_t> subscriptions;
    // OPModule *op_module = new OPModule();
    subscriptions.clear();
    for (auto each_event : NOTIFYEVENTS) {
        subscriptions.push_back(each_event.second);
    }
    CreateClient(event_callback);
    SubscribeClient(subscriptions);
    pause();
}
