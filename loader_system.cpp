#include "loader_system.h"

#include <cstdio>
#include <cstring>
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


void LoaderSystem::print_pid() const{
    std::cout << m_pid_string << '\n';
}

bool LoaderSystem::fetch_data(){
    std::ifstream target_maps_fstream("/proc/"+m_pid_string+"/maps");
    if(!target_maps_fstream){
        return false;
    }
    
    auto dlsym_lite_base = [this](std::ifstream& stream, std::string target, std::string permission)->unsigned long long{

        stream.clear();
        stream.seekg(0, std::ios::beg);

        std::string current_page{};
    
        while(getline(stream, current_page)){
            if(current_page.find(target) != std::string::npos && current_page.find(target) != std::string::npos){
                std::size_t dash_iter = current_page.find(' ');
                std::string memory_string{current_page.substr(0, dash_iter)};
                return std::stoull(memory_string, nullptr, 16);
            }
        }

        return 0;
    };

    m_sys_data.m_program_base = dlsym_lite_base(target_maps_fstream, m_program_name, "r");
    m_sys_data.m_libc_base = dlsym_lite_base(target_maps_fstream, "libc.so", "r");

    std::ifstream self_fstream("/proc/"+std::to_string(getpid())+"/maps");
    unsigned long long self_libc_base  = dlsym_lite_base(self_fstream, "libc.so", "r");

    void* self_mmap = dlsym(RTLD_DEFAULT, "mmap");
    if(!self_mmap){
        std::cerr << "couldnt find local mmap.";
        return false;
    }
    unsigned long long mmap_offset = (reinterpret_cast<unsigned long long>(self_mmap)) - self_libc_base;

    void* self_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if(!self_dlopen){
        std::cerr << "coudlnt find local dlopen";
        return false;
    }
    unsigned long long dlopen_offset = (reinterpret_cast<unsigned long long>(self_dlopen) - self_libc_base);

    m_sys_data.m_mmap_address = m_sys_data.m_libc_base + mmap_offset;
    m_sys_data.m_dlopen_address = m_sys_data.m_libc_base  + dlopen_offset;

    return true;
    }

bool LoaderSystem::ptrace_load(){

    ////////////////////////////////////////////////////////////
    /////////////////////// MMAP SECTION ///////////////////////
    ////////////////////////////////////////////////////////////

    if(ptrace(PTRACE_ATTACH, m_pid_int, nullptr, nullptr) < 0 ){
        std::cerr<< "unable to attach ptrace" <<  "\n";
        return false;
    }
    waitpid(m_pid_int, nullptr, 0);

    struct user_regs_struct backup, current, result;
    if(ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &backup) < 0){
        std::cerr << "unable to get registers #1" << "\n";
        return false;
    }

    current = backup;

    current.rax = 0x9;
    current.rdi = 0;
    current.rsi = 0x1000;
    current.rdx = 0x7;
    current.r10 = 0x22;
    current.r8 = static_cast<unsigned long long>(-1);
    current.r9 = 0;
 
    unsigned long long phase1_rip_address{current.rip};
    errno = 0;
    unsigned long long original_rip_instruction = ptrace(PTRACE_PEEKDATA, m_pid_int, reinterpret_cast<void*>(phase1_rip_address), nullptr );
    if(errno != 0){
        std::cerr << "unable to get phase1 rip instruction" << "\n";\
        return false;
    }

    unsigned long long phase1_altered_rip_instruction = (original_rip_instruction & 0xFFFFFFFFFF000000) | 0xCC050F;
    if(ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(phase1_rip_address), reinterpret_cast<void*>(phase1_altered_rip_instruction)) < 0){
        std::cerr << "unable to set phase1 new rip instruction" << "\n";
        return false;
    }

    if(ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &current) < 0){
        std::cerr << "unable to set phase1 new registers" << "\n";
        return false;
    }

    if(ptrace(PTRACE_CONT, m_pid_int, nullptr, nullptr) < 0){
        std::cerr << "unable to lift phase1 breakpoint off target" << "\n";
        return false;
    }
    waitpid(m_pid_int, nullptr, 0);

    if(ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &result) < 0){
        std::cerr << "unable to get registers for result" << "\n";
        return false;
    }

    unsigned long long allocated_address = result.rax;
    std::cout << "syscall mmap returned : 0x" << std::hex << allocated_address << std::dec << "\n";

    ////////////////////////////////////////////////////////////
    /////////////////////// WRITE PATH SECTION /////////////////
    ////////////////////////////////////////////////////////////


    const std::size_t lib_length = m_lib_path.size() + 1;
    struct iovec local_write_region{
        .iov_base = m_lib_path.data(),
        .iov_len = lib_length
    };
    struct iovec remote_write_region{
        .iov_base = reinterpret_cast<void*>(allocated_address),
        .iov_len = lib_length
    };

    ssize_t bytes_written = process_vm_writev(m_pid_int, &local_write_region, 1, &remote_write_region, 1, 0);
    if(bytes_written != lib_length){
        std::cerr << "unable to properly write lib path" << "\n";
        return false;
    }

    char written[lib_length];
    struct iovec local_read_region{
        .iov_base = written,
        .iov_len = lib_length,
    };
    struct iovec remote_read_region{
        .iov_base = reinterpret_cast<void*>(allocated_address),
        .iov_len = lib_length,
    };

    ssize_t bytes_read = process_vm_readv(m_pid_int, &local_read_region, 1, &remote_read_region, 1, 0);
    if(bytes_read != lib_length){
        std::cerr << "unable to properly read lib path" << "\n";
        return false;
    }

    std::cout << "written lib path : " <<  written << "\n";

    ////////////////////////////////////////////////////////////
    /////////////////////// DLOPEN SECTION /////////////////////
    ////////////////////////////////////////////////////////////

    current.rax = m_sys_data.m_dlopen_address;
    current.rdi = allocated_address;
    current.rsi = 0x2;

    errno = 0;
    unsigned long long phase2_rip_instruction = ptrace(PTRACE_PEEKDATA, m_pid_int, reinterpret_cast<void*>(current.rip), nullptr);
    if(errno != 0){
        std::cerr << "unable to get phase2 rip instruction";
        return false;
    }

    unsigned long long phase2_altered_rip_instruction = (phase2_rip_instruction & 0xFFFFFFFFFF000000) | 0xCCD0FF;
    if(ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(current.rip), reinterpret_cast<void*>(phase2_altered_rip_instruction)) < 0){
        std::cerr << "unable to set phase2 new instruction" << "\n";
        return false;
    }

    current.rsp = (current.rsp & 0xFFFFFFFFFFFFFFF0);
    if(ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &current) < 0){
        std::cerr << "unable to set phase2 register"  << "\n";
        return false;
    }
    
    if(ptrace(PTRACE_CONT, m_pid_int, nullptr, nullptr) <0 ){
        std::cerr << "unable to lift phase2 breakpoint off target" << "\n";
        return false;
    }
    waitpid(m_pid_int, nullptr, 0);

    std::cout << "\nJOB DONE, dlopen result isnt going to be checked for now.\n"
                 "Runtime error are most likely due to the program being run on non libc based system.\n"
                 "Will add glibc support  soon.\n"
                 "CLEANUP MECHANISM ASSUME GETREGS ON FIRST PHASE SUCCEED\n";


    if(ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(backup.rip), reinterpret_cast<void*>(original_rip_instruction)) < 0){
        std::cerr <<  "unable to store original rip instruction inside backup register." << "\n";
        return false;
    }
    if(ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &backup) < 0){
        std::cerr << "unable to set backup registers" << "\n";
        return false;
    }
    ptrace(PTRACE_DETACH, m_pid_int, nullptr, nullptr);
return true;

}
