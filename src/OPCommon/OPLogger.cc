#include"OPLogger.h"
#include <iostream>
using namespace std;
void OPLogger::WRONG(string message){
    cout << "[WRONG]: " << message << endl;
}
void OPLogger::INFO(string message){
    cout << "[INFO ]: " << message << endl;
}
void OPLogger::DEBUG(string message){
    if(is_debug_){
        cout << "[DEBUG]: " << message << endl;
    }
}
void OPLogger::ERROR(string message){
    cout << "[ERROR]: " << message << endl;
}