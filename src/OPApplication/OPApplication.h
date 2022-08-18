
#include<iostream>
#include<string>

using namespace std;
string OPApplication_path = "./OPApplication";
string OPScanner_path = "./OPScanner.dylib";

void* gScannerLib;

typedef int (*fnScannerStart)();

fnScannerStart pfnScannerStart;