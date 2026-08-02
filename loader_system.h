#ifndef UNIFIED
#define UNIFIED
#include <dlfcn.h>
#include <ios>
#include <memory>
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
#include <vector>

struct SysData{
    unsigned long long m_program_base{};
    unsigned long long m_libc_base{};
    unsigned long long m_custom_base{};
    unsigned long long m_dlopen_address{};
    unsigned long long m_mmap_address{};
};

enum class ErrorFlag : std::size_t {
    ATTACH,
    GETREG,
    SETREG,
    READRIP,
    SETRIP,
    READV,
    WRITEV,
    CONT,
    DETACH,
};

class IErrorReport{
public:
    virtual void raise_error(ErrorFlag flag) = 0;
    virtual ~IErrorReport() = default;
};

class Session : IErrorReport{
private:
    class LoaderSystem{
    private:
        std::string m_pid_string{};
        int m_pid_int{};
        std::string m_program_name{};
        std::string m_lib_path{};
        SysData m_sys_data{};

        void clear_sys_data(){
            m_sys_data = SysData{};
        }

    public:
        explicit LoaderSystem(std::string&& pid_string, int pid_int,  std::string&& program_name, std::string&& lib_path) : 
            m_pid_string{std::move(pid_string)},
            m_pid_int{pid_int},
            m_program_name{std::move(program_name)},
            m_lib_path{std::move(lib_path)}
            {}
        friend Session;
        LoaderSystem() = delete;
        bool fetch_data(IErrorReport& report_interface);
        bool ptrace_load(IErrorReport& report_interface);
    };

    std::unique_ptr<LoaderSystem> m_protected_system;
    std::vector<ErrorFlag> m_error_container{};

public:

    void raise_error(ErrorFlag flag){
        m_error_container.push_back(flag);
    }

    static std::optional<Session> create_protected_environment(std::string process_name, std::string path_to_lib){
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
                    Session temporary;

                    temporary.m_protected_system = std::unique_ptr<LoaderSystem>( 
                        new LoaderSystem{
                            
                        std::move(proc_entry.path().filename().string()),
                           std::stoi(proc_entry.path().filename().string()),
                      std::move(process_name),
                          std::move(lib_fs.string())
                        } 
                    );

                    return std::move(temporary);
                }
            }
        return std::nullopt;
    }

    void safe_fetch_data(){
        m_protected_system->fetch_data(*this);
    }
    void safe_ptrace_load(){
        std::cout << "target dlopen address 0x " << m_protected_system->m_sys_data.m_dlopen_address << "\n";
        m_protected_system->ptrace_load(*this);
    }

};



#endif