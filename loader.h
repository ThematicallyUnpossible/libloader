#ifndef LOADER
#define LOADER

#include <cstddef>
#include <fstream>
#include <iostream>
#include <optional>
#include <filesystem>
#include <string>
#include <sys/ptrace.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <cerrno>
#include <cstring>
#include <algorithm>

struct ProcessInfo{
    std::string m_pid_string{};
    int m_pid_int{};
    unsigned long long m_base_address{};
    unsigned long long m_libc_address{};
    unsigned long long m_dlopen_address{};
    unsigned long long m_mmap_address{};
};

inline std::optional<ProcessInfo> get_process_info(std::string_view proc_name){

    for(const auto& dir : std::filesystem::directory_iterator{"/proc/"}){

        std::ifstream dir_comm(dir.path() / "comm");
        
        std::string dir_comm_string{};
        
        std::getline(dir_comm, dir_comm_string);

        if(dir_comm_string.find(proc_name) != std::string::npos){

            ProcessInfo temp{};

            temp.m_pid_string = dir.path().filename().string();

            temp.m_pid_int = std::stoi(temp.m_pid_string);

            std::ifstream maps_fstream("/proc/" + temp.m_pid_string + "/maps");

            std::string first_page{};

            std::getline(maps_fstream, first_page);

            std::size_t dash_iter = first_page.find('-');

            std::string address_string = first_page.substr(0, dash_iter);

            temp.m_base_address = std::stoull(address_string, nullptr, 16);

            std::string current_page{};
            while(getline(maps_fstream, current_page)){

                if(current_page.find("libc") != std::string::npos&&
                current_page.find("r-xp") != std::string::npos
                    ){
                    std::size_t current_dash_iter = current_page.find('-');
                    std::string libc_base{current_page.substr(0, current_dash_iter)};
                    unsigned long long libc_base_address = std::stoull(libc_base, nullptr,16);
                    temp.m_libc_address = libc_base_address;
                }
            }
            maps_fstream.close();

            auto self_pid = getpid();
            std::ifstream self_maps("/proc/" + std::to_string(self_pid) + "/maps");

            std::string line;
            unsigned long long self_libc_base = 0;

            while (std::getline(self_maps, line)) {
                if (line.find("libc") != std::string::npos && 
                    line.find("r-xp") != std::string::npos) {
                    std::size_t dash = line.find('-');
                    self_libc_base = std::stoull(line.substr(0, dash), nullptr, 16);
                    break;
                }
            }
            
            void* dlopen = dlsym(RTLD_DEFAULT, "dlopen");

            unsigned long long dlopen_universal_offset = reinterpret_cast<unsigned long long>(dlopen) - self_libc_base;

            temp.m_dlopen_address = temp.m_libc_address + dlopen_universal_offset;

            void* mmap = dlsym(RTLD_DEFAULT, "mmap");

            unsigned long long mmap_universal_offset = reinterpret_cast<unsigned long long>(mmap) - self_libc_base;

            temp.m_mmap_address = temp.m_libc_address + mmap_universal_offset;

            return temp;
        }
    }
    return std::nullopt;
}

inline bool load_library(ProcessInfo& minfo, std::string path) {
    
    if(ptrace(PTRACE_ATTACH, minfo.m_pid_int, nullptr, nullptr) < 0){
        std::cerr << "~Ptrace failed to attach\n";
        return false;
    }
    waitpid(minfo.m_pid_int, nullptr, 0);
    std::cout << "*Attached ptrace\n";

    struct user_regs_struct backup, main;

    if(ptrace(PTRACE_GETREGS, minfo.m_pid_int, nullptr, &backup) < 0){
        std::cerr << "~Ptrace failed to get registers\n";
        return false;
    }

    main = backup;

    unsigned long long original_rip_address = backup.rip;
    
    errno = 0;
    unsigned long long original_rip_instruction = ptrace(PTRACE_PEEKDATA, minfo.m_pid_int, (void*)original_rip_address, nullptr);
    if (errno != 0) {
        std::cerr << "~Ptrace failed to get instructions from the original rip address\n";
        return false;
    }

    unsigned long long altered_rip_instruction = (original_rip_instruction & 0xFFFFFFFFFF000000) | 0xCC050F;
    if(ptrace(PTRACE_POKEDATA, minfo.m_pid_int, (void*)original_rip_address, (void*)altered_rip_instruction) < 0){
        std::cerr << "~Ptrace failed to write new rip instruction\n";
        return false;
    }
    std::cout << "*Wrote new instruction at current rip\n";

    main.rax = 0x9; 
    main.rdi = 0x0; 
    main.rsi = 0x1000;
    main.rdx = 0x7;
    main.r10 = 0x22;
    main.r8 = (unsigned long long)-1;
    main.r9 = 0;

    if(ptrace(PTRACE_SETREGS, minfo.m_pid_int, nullptr, &main) < 0 ){
        std::cerr << "~Ptrace unable to set the new register to fulfill systemcall.\n";
        return false;
    }
    std::cout << "*Wrote new registers\n";

    ptrace(PTRACE_CONT, minfo.m_pid_int, nullptr, nullptr);
    waitpid(minfo.m_pid_int, nullptr, 0);
    std::cout << "*Breakpoint triggered.\n";

    struct user_regs_struct result;
    if(ptrace(PTRACE_GETREGS, minfo.m_pid_int, nullptr, &result) < 0){
        std::cerr << "~Ptrace failed to get registers\n";
        return false;
    }

    std::cout << "*Allocated at 0x" << std::hex << result.rax << std::dec << '\n';

    int path_size = path.size() + 1;
    for(int i{}; i < path_size; i += 8){
        int used_byte_count = std::min(8, (path_size - i));
        unsigned long long memory_string_address{};
        memcpy(&memory_string_address, path.data() + i, used_byte_count);
        if(ptrace(PTRACE_POKEDATA, minfo.m_pid_int, (void*)(result.rax + i), (void*)memory_string_address) < 0){
            std::cerr << "~Ptrace failed to write at string offset : " << i << "\n";
            return false;
        }
    }

    char written_string[256] = {};
    struct iovec local_read_region{
        .iov_base = written_string,
        .iov_len = (std::size_t)path_size,
    };
    struct iovec remote_read_region{
        .iov_base = (void*)result.rax,
        .iov_len = (std::size_t)path_size,
    };

    process_vm_readv(minfo.m_pid_int, &local_read_region, 1, &remote_read_region, 1, 0);

    std::cout << "*Written string : " << written_string << '\n';


    ptrace(PTRACE_POKEDATA, minfo.m_pid_int, (void*)original_rip_address, (void*)original_rip_instruction);
    ptrace(PTRACE_SETREGS, minfo.m_pid_int, nullptr, &backup);

    //ill now attempt to try dlopen and implement the stack alignment prochedure

    unsigned long long phase2_original_rip_address = main.rip;

    errno = 0;
    unsigned long long phase2_original_rip_instruction = ptrace(PTRACE_PEEKDATA, minfo.m_pid_int, (void*)main.rip, nullptr);
    if(errno != 0){
        std::cerr << "~Ptrace failed to fetch phase 2 rip original instruction. : " << strerror(errno);
        return false;
    }

    unsigned long long phase2_altered_rip_instruction = ( phase2_original_rip_instruction & 0xFFFFFFFFFF000000 ) | 0xCCD0FF;

    if(ptrace(PTRACE_POKEDATA, minfo.m_pid_int, (void*)original_rip_address, (void*)phase2_altered_rip_instruction)  < 0 ){
        std::cerr << "~Ptrace failed to write phase two rip's new instruction\n";
        return false;
    }

    main.rax = minfo.m_dlopen_address;
    main.rdi = result.rax;
    main.rsi = (unsigned long long)2;
    main.rsp = main.rsp & 0xFFFFFFFFFFFFFFF0;

    if(ptrace(PTRACE_SETREGS, minfo.m_pid_int, nullptr, &main) < 0){
        std::cerr << "~Ptrace failed to set dlopen registers\n";
        return false;
    }
    std::cout << "*Dlopen registers ready, ";

    if(ptrace(PTRACE_SETREGS, minfo.m_pid_int, nullptr, &main) < 0){
        std::cerr << "~Ptrace failed to write phase 2 new register\n";
        return false;
    }
    std::cout << "invoking.. ";

    ptrace(PTRACE_CONT, minfo.m_pid_int, nullptr, nullptr);
    waitpid(minfo.m_pid_int, nullptr, 0);

    std::cout << "done.\n";

    ptrace(PTRACE_POKEDATA, minfo.m_pid_int, (void*)original_rip_address, (void*)original_rip_instruction);
    ptrace(PTRACE_SETREGS, minfo.m_pid_int, nullptr, &backup);
    ptrace(PTRACE_DETACH, minfo.m_pid_int, nullptr, nullptr);

    return true;
}




#endif 