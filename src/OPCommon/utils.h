#include<string>
#include<iostream>
#include <cstdint>
#include <filesystem>
#include <EndpointSecurity/EndpointSecurity.h>
namespace fs = std::filesystem;

using namespace std;
namespace OPUtils{
    string TimespecToString(time_t time);
    string EsStringTokenToStr( es_string_token_t src );
    string EsFileToStr( es_file_t * src );
    bool IsProtectedDirectory(string path);
    void PopAlertMessage(string title,string alert);
    bool IsIncludeTCCDirectory(string path);
    bool op_delete(const std::filesystem::path& target_path );
    bool op_write(const std::filesystem::path& target_path,string content );
}