#include<string>
using namespace std;
class OPLogger{
public:
    static OPLogger& GetInstance() {
        static OPLogger sInstance;
        return sInstance;
    }
    void WRONG(string message);
    void INFO(string message);
    void DEBUG(string message);
    void ERROR(string message);
private:
    bool is_debug_ = true;
};

