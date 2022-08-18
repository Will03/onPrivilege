#include <iostream>
#include <string>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include "OPApplication.h"
#include "../OPCommon/OPSQLite.h"
#include "../OPCommon/utils.h"
#include "../OPCommon/OPLogger.h"
#include <iostream>
#include <fstream>

using namespace std;

void ShowBanner(){
cout << "===================================================" << endl;
cout << "            ______     _       _ _                 " << endl;
cout << "            | ___ \\   (_)     (_) |                " << endl;
cout << "  ___  _ __ | |_/ / __ ___   ___| | ___  __ _  ___ " << endl;
cout << " / _ \\| '_ \\|  __/ '__| \\ \\ / / | |/ _ \\/ _` |/ _ \\" << endl;
cout << "| (_) | | | | |  | |  | |\\ V /| | |  __/ (_| |  __/" << endl;
cout << " \\___/|_| |_\\_|  |_|  |_| \\_/ |_|_|\\___|\\__, |\\___|" << endl;
cout << "                                         __/ |     " << endl;
cout << "                                        |___/      " << endl;
cout << "===================================================" << endl;

}

int LoadScanner()
{
    OPLogger::GetInstance().INFO("Load scanner");
    gScannerLib = dlopen(OPScanner_path.c_str(), RTLD_LAZY);
    if (!gScannerLib)
    {
        cerr << "Load library error: " << errno << endl;
    }
    pfnScannerStart = (fnScannerStart)dlsym(gScannerLib, "ScannerStart");
    if (!pfnScannerStart)
    {
        cerr << "Load symbol error: " << errno << endl;
    }
    pfnScannerStart();
}

int InitProc()
{
    OPLogger::GetInstance().INFO("InitProc");
    OPUtils::op_write("./pid", to_string(getpid()));
    OPUtils::op_delete("./.onPrivilege.sqlite");
}

int main(int argc, char **argv)
{

    // InitLog();
    ShowBanner();
    InitProc();
    OPSQLite sql;
    sql.CreateTable();
    LoadScanner();
}