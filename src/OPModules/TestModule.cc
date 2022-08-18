#include "TestModule.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <string>
using namespace std;

bool TestModule::event_callback(const Event &event) {
    OutputProc(event);
}

void TestModule::ModuleStart() {
    std::vector<es_event_type_t> subscriptions;
    subscriptions.clear();
    for (auto each_event : NOTIFYEVENTS) {
        subscriptions.push_back(each_event.second);
    }
    CreateClient(event_callback);
    SubscribeClient(subscriptions);
    pause();
}
