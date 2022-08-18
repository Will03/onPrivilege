#include "utils.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>
#include "../OPCommon/OPLogger.h"

using namespace std;
// filesystem
namespace OPUtils
{
    string TimespecToString(time_t time)
    {
        char str_time[256];
        strftime(str_time, sizeof(str_time) - 1, "%Y-%m-%d %H:%M:%S", std::localtime(&time));
        return str_time;
    }
    string EsStringTokenToStr(es_string_token_t src)
    {
        if (src.length > 0)
            return src.data;
        else
            return "";
    }
    string EsFileToStr(es_file_t *src)
    {
        if (src)
            return EsStringTokenToStr(src->path);
        else
            return "";
    }
    void HookingPIDRegister(pid_t pid)
    {
        if (!pid)
        {
            return;
        }
    }
    bool IsProtectedDirectory(string path)
    {
        if(path.find("/usr/local/etc") !=  string::npos){
            return true;
        }
        return false;
    }
    bool IsIncludeTCCDirectory(string path){
        if(path.find("com.apple.TCC") !=  string::npos){
            return true;
        }
        return false;
    }

    void PopAlertMessage(string title,string alert){
        string cmd = "osascript -e 'display notification \""+ alert +"\" with title \"" + title + "\"'";
        system(cmd.c_str());
    }

    bool op_delete(const std::filesystem::path& target_path ){
        if(fs::exists(target_path)){
            std::uintmax_t n = fs::remove(target_path);
        }
    }
    bool op_write(const std::filesystem::path& target_path,string content ){
        ofstream my_file;
        my_file.open (target_path);
        my_file << content;
        my_file.close();
    }

}