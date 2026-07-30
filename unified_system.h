#ifndef UNIFIED
#define UNIFIED
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <ios>
#include <optional>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/uio.h>

struct SysData{
    unsigned long long m_program_base{};
    unsigned long long m_libc_base{};
    unsigned long long m_custom_base{};
    unsigned long long m_dlopen_address{};
    unsigned long long m_mmap_address{};
};

class System{

private:
    std::string m_pid_string{};
    int m_pid_int{};
    std::string m_program_name{};
    std::string m_lib_path{};
    SysData m_sys_data{};

    System(std::string&& pid_string, int pid_int,  std::string&& program_name, std::string&& lib_path) : 
    m_pid_string{std::move(pid_string)},
    m_pid_int{pid_int},
    m_program_name{std::move(program_name)},
    m_lib_path{std::move(lib_path)}
    {
        //nothing here
    }

    void clear_sys_data(){
        m_sys_data = SysData{};
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
            return System{
                std::move(proc_entry.path().filename().string()),
                std::stoi(proc_entry.path().filename().string()),
                std::move(process_name),
                std::move(lib_fs.string())
            };
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

    m_sys_data.m_program_base = dlsym_lite_base( m_program_name, "r");
    m_sys_data.m_libc_base = dlsym_lite_base("libc.so", "r");


    //figuring out offset

    std::ifstream self_fstream("/proc/"+std::to_string(getpid())+"/maps");
    std::string first_page {};
    getline(self_fstream, first_page);
    std::size_t self_dash_index = first_page.find('-');
    std::string self_program_base_string = first_page.substr(0, self_dash_index);

    unsigned long long self_program_base = std::stoull(self_program_base_string, nullptr, 16);

    void* self_mmap = dlsym(RTLD_DEFAULT, "mmap");
    if(!self_mmap){
        std::cerr << "couldnt find local mmap.";
        return false;
    }
    unsigned long long mmap_offset = (*static_cast<unsigned long long*>(self_mmap)) - self_program_base;

    void* self_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if(!self_dlopen){
        std::cerr << "coudlnt find local dlopen";
        return false;
    }
    unsigned long long dlopen_offset = (*static_cast<unsigned long long*>(self_dlopen) - self_program_base);

    m_sys_data.m_mmap_address = m_sys_data.m_libc_base + mmap_offset;
    m_sys_data.m_dlopen_address = m_sys_data.m_libc_base  + dlopen_offset;

    return true;
    }

bool ptrace_load(){
    ptrace(PTRACE_ATTACH, m_pid_int, nullptr, nullptr);
    waitpid(m_pid_int, nullptr, 0);
    std::cout << "attached ptrace." << "\n";

    struct user_regs_struct backup, used;
    if(ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &used) < 0){
        std::cerr << "unable to get registers #1" << "\n";
        return false;
    }

    backup = used;

    used.rax = 0x9;
    used.rdi = 0;
    used.rsi = 0x1000;
    used.rdx = 0x7;
    used.r10 = 0x22;
    used.r8 = static_cast<unsigned long long>(-1);
    used.r9 = 0;
 
 
    errno = 0;
    unsigned long long phase1_original_rip = ptrace(PTRACE_PEEKDATA, m_pid_int, reinterpret_cast<void*>(used.rip), nullptr);
    if(errno != 0){
        std::cerr << "unable to get phase 1 rip instruction : " << strerror(errno) << "\n";
        return false;
    }
    std::cout << "current rip instruction : " << std::hex << phase1_original_rip << std::dec << "\n";

    unsigned long long phase1_modified_rip = (phase1_original_rip & 0xFFFFFFFFFF000000) | 0xCC050F;
    if(ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(used.rip), reinterpret_cast<void*>(phase1_modified_rip)) < 0 ){
        std::cerr << "unable to modify phase 1 rip instruction" << "\n";
        return false;
    }
    std::cout << "new rip instruction : " << phase1_modified_rip << "\n";

    if(ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &used) < 0){
        std::cerr << "failed to set new register" << "\n";
        return false;
    }

    std::cout << "ptrace succesfully set new register." << "\n";
    std::cout << "assumed mmap address : 0x" << std::hex << m_sys_data.m_mmap_address << std::dec << "\n";

    ptrace(PTRACE_CONT, m_pid_int, nullptr, nullptr);
    waitpid(m_pid_int, nullptr, 0);

    std::cout << "target program triggered 0xCC." << "\n";

    struct user_regs_struct result;
    ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &result);

    unsigned long long allocated = result.rax;
    std::cout << "allocated region for string path at 0x" << std::hex << allocated <<  std::dec <<  "\n";

    struct iovec local_iov {
        .iov_base = (void*)m_lib_path.data(),
        .iov_len  = m_lib_path.size() + 1   
    };
    struct iovec remote_iov {
        .iov_base = (void*)allocated,
        .iov_len  = m_lib_path.size() + 1
    };

    ssize_t written = process_vm_writev(m_pid_int, &local_iov, 1, &remote_iov, 1, 0);
    if (written == -1) {
        std::cerr << "process_vm_writev failed." << "\n";
        return false;
    }

    ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(backup.rip), reinterpret_cast<void*>(phase1_original_rip));
    //reset it to make sure dl open have no issue

    used = backup;

    used.rax = m_sys_data.m_dlopen_address;
    used.rdi = allocated;
    used.rsi = 0x2;


    errno = 0;
    unsigned long long phase2_original_rip = ptrace(PTRACE_PEEKDATA, m_pid_int, reinterpret_cast<void*>(used.rip), nullptr);
    if(errno != 0){
        std::cerr << "unable to get phase 2 rip instruction : " << strerror(errno) << "\n";
        return false;
    }                   
    std::cout << "current rip instruction : " << std::hex << phase2_original_rip << std::dec << "\n";

    unsigned long long phase2_modified_rip = (phase2_original_rip & 0xFFFFFFFFFF000000) | 0xCCD0FF;
    if(ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(used.rip), reinterpret_cast<void*>(phase2_modified_rip)) < 0){
        std::cerr << "unable to modify phase 2 rip instruction" << "\n";
        return false;
    }
    std::cout << "new rip instruction : " << std::hex << phase2_modified_rip << std::dec << "\n";

    std::cout << "assumed dlopen address : 0x" << std::hex << m_sys_data.m_dlopen_address << std::dec << "\n"; 
    used.rsp = used.rsp & 0xFFFFFFFFFFFFFFF0;
    std::cout << "stack aligned : 0x" << std::hex << used.rsp << std::dec << "\n"; 


    


     




    ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &used);
    ptrace(PTRACE_CONT, m_pid_int, nullptr, nullptr);
    waitpid(m_pid_int, nullptr, 0);
    std::cout << "target program triggered 0xCC\n";


    ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &result);
    std::cout << std::hex <<  result.rax << std::dec << "\n";











    ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(backup.rip), reinterpret_cast<void*>(phase1_original_rip));
    ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &backup);
    ptrace(PTRACE_DETACH, m_pid_int, nullptr, nullptr);

    return true;
}

};







#endif