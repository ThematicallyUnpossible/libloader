#ifndef UNIFIED
#define UNIFIED
#include <dlfcn.h>
#include <ios>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/uio.h>
#include <optional>
#include <filesystem>

struct SysData{
    unsigned long long m_program_base{};
    unsigned long long m_libc_base{};
    unsigned long long m_custom_base{};
    unsigned long long m_dlopen_address{};
    unsigned long long m_mmap_address{};
};

struct Session{
    bool m_attached{};
    bool m_phase1_get_register{};
    bool m_phase1_set_register{};
    bool m_phase2_get_register{};
    bool m_phase2_set_register{};
};

class LoaderSystem{

private:
    std::string m_pid_string{};
    int m_pid_int{};
    std::string m_program_name{};
    std::string m_lib_path{};
    SysData m_sys_data{};

    explicit LoaderSystem(std::string&& pid_string, int pid_int,  std::string&& program_name, std::string&& lib_path) : 
    m_pid_string{std::move(pid_string)},
    m_pid_int{pid_int},
    m_program_name{std::move(program_name)},
    m_lib_path{std::move(lib_path)}
    {
        //nothing here
    } 

    void ptrace_load_clean(bool overwritten_data, unsigned long long original_rip_instruction, user_regs_struct& backup);

    void clear_sys_data(){
        m_sys_data = SysData{};
    }

public:

static std::optional<LoaderSystem> initialize(std::string process_name, std::string path_to_lib){
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
            return LoaderSystem{
                std::move(proc_entry.path().filename().string()),
                std::stoi(proc_entry.path().filename().string()),
                std::move(process_name),
                std::move(lib_fs.string())
            };
        }
    }
    return std::nullopt;
}

LoaderSystem() = delete;

void print_pid() const;

bool fetch_data();

bool ptrace_load();


};





#endif