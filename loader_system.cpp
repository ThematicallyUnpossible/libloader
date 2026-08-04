#include "loader_system.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <ios>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <algorithm>



bool Session::do_cleanup(){
    
    bool require_patching{false};

    auto readrip_occurances = std::count(m_checkpoint_container.begin(), m_checkpoint_container.end(), Checkpoint::GETRIP);
    auto setrip_occurances = std::count(m_checkpoint_container.begin(), m_checkpoint_container.end(), Checkpoint::SETRIP);
    auto getreg_occurances = std::count(m_checkpoint_container.begin(), m_checkpoint_container.end(), Checkpoint::GETREG);
    auto setreg_occurances = std::count(m_checkpoint_container.begin(), m_checkpoint_container.end(), Checkpoint::SETREG);

    if(readrip_occurances > 1 || setrip_occurances > 0 || getreg_occurances > 1 || setreg_occurances > 0){
        require_patching = true;
    }
    
    if(require_patching){
        if(ptrace(PTRACE_POKEDATA, m_protected_system->m_pid_int, reinterpret_cast<void*>(m_protected_system->m_reg_data.m_backup.rip), reinterpret_cast<void*>((m_protected_system->m_sys_data.m_original_rip_instruction))) < 0){
            std::cerr <<  "unable to store original rip instruction inside backup register." << "\n";
            return false;        
        }
    }

    if(ptrace(PTRACE_SETREGS, m_protected_system->m_pid_int, nullptr, &m_protected_system->m_reg_data.m_backup) < 0){
            std::cerr << "unable to set backup registers" << "\n";
            return false;        
        }
        ptrace(PTRACE_DETACH, m_protected_system->m_pid_int, nullptr, nullptr);
    return true;
}

bool Session::LoaderSystem::fetch_data(SessionInterfaces& session_interface){
    std::ifstream target_maps_fstream("/proc/"+m_pid_string+"/maps");
    if(!target_maps_fstream){
        return false;
    }
    
    auto dlsym_lite_base = [this](std::ifstream& stream, std::string target, std::string permission)->unsigned long long{

        stream.clear();
        stream.seekg(0, std::ios::beg);

        std::string current_page{};
    
        while(getline(stream, current_page)){
            if(current_page.find(target) != std::string::npos && current_page.find(permission) != std::string::npos){
                std::size_t dash_iter = current_page.find('-');
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


bool Session::LoaderSystem::trigger_hook(SessionInterfaces& session_interface, std::string& lib_name){
    

    std::string path_to_maps = "/proc/"  +  m_pid_string  +  "/maps";
    std::fstream maps_fstream(path_to_maps);
    if(!maps_fstream){
        std::cerr << "invalid maps path" <<  "\n";
        return false;
    }
    std::string current_page;
    while(getline(maps_fstream,  current_page)){
        if(current_page.find(lib_name) != std::string::npos){
            std::size_t dash_index = current_page.find('-');
            std::string base_addr_string =   current_page.substr(0, dash_index);
            m_sys_data.m_custom_base = (std::stoull(base_addr_string,  nullptr, 16));
            break;
        }
    }
    
    //1119 offset to hook fcn
    //2377 offset to original fcn

    char bytes_to_write[14];
    bytes_to_write[0] = 0xFF;
    bytes_to_write[1] = 0x25;
    bytes_to_write[2] = 0x00;
    bytes_to_write[3] = 0x00;
    bytes_to_write[4] = 0x00;
    bytes_to_write[5] = 0x00;


    unsigned long long hook_address = m_sys_data.m_custom_base + 0x1119;


    memcpy(&bytes_to_write[6], &hook_address, 8);
    std::string path_to_memory = "/proc/"+m_pid_string+"/mem";
    int fd  = open(path_to_memory.c_str(), O_WRONLY);
    if(fd < 0){
        std::cerr << "failed to open file  descriptor of target mem" << "\n";
        return false;
    }

    unsigned long long original_function = m_sys_data.m_program_base + 0x2377;

    lseek(fd, original_function, SEEK_SET);
    write(fd, &bytes_to_write, 14);
    
    

    return true;
}


bool Session::LoaderSystem::ptrace_load(SessionInterfaces& session_interface){

    ////////////////////////////////////////////////////////////
    /////////////////////// MMAP SECTION ///////////////////////
    ////////////////////////////////////////////////////////////

    if(ptrace(PTRACE_ATTACH, m_pid_int, nullptr, nullptr) < 0 ){
        std::cerr<< "unable to attach ptrace" <<  "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::ATTACH);
    waitpid(m_pid_int, nullptr, 0);

    if(ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &m_reg_data.m_backup) < 0){
        std::cerr << "unable to get registers #1" << "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::GETREG);

    m_reg_data.m_used = m_reg_data.m_backup;

    m_reg_data.m_used.rax = 0x9;
    m_reg_data.m_used.rdi = 0;
    m_reg_data.m_used.rsi = 0x1000;
    m_reg_data.m_used.rdx = 0x7;
    m_reg_data.m_used.r10 = 0x22;
    m_reg_data.m_used.r8 = static_cast<unsigned long long>(-1);
    m_reg_data.m_used.r9 = 0;
 
    unsigned long long phase1_rip_address{m_reg_data.m_used.rip};
    errno = 0;
    m_sys_data.m_original_rip_instruction = ptrace(PTRACE_PEEKDATA, m_pid_int, reinterpret_cast<void*>(phase1_rip_address), nullptr );
    if(errno != 0){
        std::cerr << "unable to get phase1 rip instruction" << "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::GETREG);

    unsigned long long phase1_altered_rip_instruction = (m_sys_data.m_original_rip_instruction & 0xFFFFFFFFFF000000) | 0xCC050F;
    if(ptrace(PTRACE_POKEDATA, m_pid_int, reinterpret_cast<void*>(phase1_rip_address), reinterpret_cast<void*>(phase1_altered_rip_instruction)) < 0){
        std::cerr << "unable to set phase1 new rip instruction" << "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::SETRIP);


    if(ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &m_reg_data.m_used) < 0){
        std::cerr << "unable to set phase1 new registers" << "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::SETREG);


    if(ptrace(PTRACE_CONT, m_pid_int, nullptr, nullptr) < 0){
        std::cerr << "unable to lift phase1 breakpoint off target" << "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::CONT);
    waitpid(m_pid_int, nullptr, 0);

    if(ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &m_reg_data.m_result) < 0){
        std::cerr << "unable to get registers for result" << "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::GETREG);
    

    unsigned long long allocated_address = m_reg_data.m_result.rax;
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
    session_interface.raise_checkpoint(Checkpoint::WRITEV);


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
    session_interface.raise_checkpoint(Checkpoint::READV);


    std::cout << "written lib path : " <<  written << "\n";

    ////////////////////////////////////////////////////////////
    /////////////////////// DLOPEN SECTION /////////////////////
    ////////////////////////////////////////////////////////////

    m_reg_data.m_used.rax = m_sys_data.m_dlopen_address;
    m_reg_data.m_used.rdi = allocated_address;
    m_reg_data.m_used.rsi = 0x2;  
    m_reg_data.m_used.rsp = (m_reg_data.m_used.rsp & 0xFFFFFFFFFFFFFFF0);

    unsigned long long phase2_instruction = (m_reg_data.m_used.rip & 0xFFFFFFFFFF000000) | 0xCCD0FF;
    if (ptrace(PTRACE_POKEDATA, m_pid_int,reinterpret_cast<void*>(m_reg_data.m_used.rip), reinterpret_cast<void*>(phase2_instruction)) < 0) {
        std::cerr << "unable to set phase2 new instruction\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::SETRIP);


    if (ptrace(PTRACE_SETREGS, m_pid_int, nullptr, &m_reg_data.m_used) < 0) {
        std::cerr << "unable to set phase2 register\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::SETREG);

    if (ptrace(PTRACE_CONT, m_pid_int, nullptr, nullptr) < 0) {
        std::cerr << "unable to lift phase2 breakpoint off target\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::CONT);

    waitpid(m_pid_int, nullptr, 0);

    if(ptrace(PTRACE_GETREGS, m_pid_int, nullptr, &m_reg_data.m_result) < 0){
        std::cerr << "unable to get registers for result" << "\n";
        return false;
    }
    session_interface.raise_checkpoint(Checkpoint::GETREG);
    
    unsigned long long raw_dlopen_return = m_reg_data.m_result.rax;

    void* handle_dlopen_return = reinterpret_cast<void*>(raw_dlopen_return);
    if(!handle_dlopen_return){
        std::cerr << "nonsys call dlopen failed.";
        return false;
    }

    std::cout << "\nJOB DONE\n";

return true;

}

