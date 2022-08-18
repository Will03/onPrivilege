#include <iostream>
#include <unistd.h>
#include "OPScanner.h"
#include <map>
#include <string>
#include <dispatch/dispatch.h>

#include "../OPModules/TestModule.h"
#include "../OPModules/BypassGKModule.h"
#include "../OPModules/RootingDetectModule.h"
#include "../OPModules/TCCBypassDetectModule.h"

using namespace std;


extern "C" __attribute__((visibility("default"))) void ScannerStart(){
    //TestModule *test_module = new TestModule();
    BypassGKModule *bypass_gk_module = new BypassGKModule();
    RootingDetectModule *rooting_module = new RootingDetectModule();
    TCCBypassDetectModule *tcc_module = new TCCBypassDetectModule();

    
    cout  << "Start module" << endl;

    // By using apple GCD we can create multi-thread, but now still have some problem
    // dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_CONCURRENT_WITH_AUTORELEASE_POOL, QOS_CLASS_USER_INITIATED, 0);
    // dispatch_queue_t module = dispatch_queue_create("module", attr);
    // dispatch_async(module, ^{
    //     test_module->ModuleStart();
    // });
    //dispatch_async(module, ^{
        
    //});

    // rooting_module->ModuleStart();
    tcc_module->ModuleStart();

    cout << "finish" << endl;
    pause();
}
