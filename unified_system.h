#ifndef UNIFIED
#define UNIFIED
#include <filesystem>
#include <optional>
#include <string>
#include <iostream>
#include <fstream>

struct SysData{
    unsigned long long m_program_base{};
    unsigned long long m_libc_base{};
};

class System{

private:
    std::string m_pid_string{};
    SysData m_sys_data{};

    System(std::string&& string) : m_pid_string{std::move(string)}
    {
        //nothing here
    }

public:

static std::optional<System> initialize(std::string process_name, std::string path_to_lib){
    std::filesystem::path lib_fs = path_to_lib;
    if(!std::filesystem::exists(path_to_lib)){
        std::cerr << "erorr\n";
        return std::nullopt;
    }

    for(const auto& proc_entry : std::filesystem::directory_iterator("/proc")){
        std::ifstream entry_fstream(proc_entry.path() / "comm");
        if(!entry_fstream){
            continue;
        }
        std::string comm_string{};
        std::getline(entry_fstream, comm_string);
        if(comm_string.find(process_name) != std::string::npos){
            return System(std::move(proc_entry.path().filename().string()));
        }
    }
    return std::nullopt;
} 

System() = delete;

void print_pid() const{
    std::cout << m_pid_string << '\n';
}

bool fetch_data(){
    std::ifstream maps_fstream("/proc/"+m_pid_string+"/maps");
    if(!maps_fstream){
        return false;
    }
    
    auto dlsym_lite_base = [this, &maps_fstream](std::string target, std::string permission)->unsigned long long{

        maps_fstream.clear();
        maps_fstream.seekg(0, std::ios::beg);

        std::string current_page{};
    
        while(getline(maps_fstream, current_page)){
            if(current_page.find(target) != std::string::npos && current_page.find(target) != std::string::npos){
                std::size_t dash_iter = current_page.find(' ');
                std::string memory_string{current_page.substr(0, dash_iter)};
                return std::stoull(memory_string, nullptr, 16);
            }
        }

        return 0;
    };
    m_sys_data.m_program_base = dlsym_lite_base("DebugMe", "r");
    unsigned long long target_libc = dlsym_lite_base("libc.so", "r");


    return true;
    }

};







#endif