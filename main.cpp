#include <iostream>
#include "loader_system.h"
#include "utility.h"




#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
void parse_elf(){

    int elf_fd = open("/home/fernando/Downloads/libfcnhook.so", O_RDONLY); 
    if(elf_fd < 0){
        std::cerr << "cant open lib";
        return; 
    }


    Elf64_Ehdr elf_struct{};

    ssize_t bytes_read = read(elf_fd, &elf_struct, sizeof(Elf64_Ehdr));
    if(bytes_read != sizeof(elf_struct)){
        std::cerr << "unable to properly read elf header";
        return;
    }

    std::cout << std::hex << elf_struct.e_ident[ELFMAG0] << std::dec << "\n" <<
                 std::hex << elf_struct.e_ident[ELFMAG1] << "\n" <<
                 std::hex << elf_struct.e_ident[ELFMAG2] << "\n" <<
                 std::hex << elf_struct.e_ident[ELFMAG3] << "\n";
                             


}

int main(int argc, const char* argv[]){

    if(argc != 3){
        std::cerr << "Invalid usage. Expected : sudo ./libloader <process name> <lib_path>\n";
        return 1;
    }

    std::optional<Session>  main_session = Session::create_protected_environment(argv[1], argv[2]);
    if(!main_session){
        std::cerr << "Unable to create session,  double check arguments.\n";
        return 1;
    }

    parse_elf();
    return 2;

    while(true){
        auto operation = get_choice();
        if(operation.m_operation_enum == Operation::PTRACE_LOAD){
            main_session->safe_fetch_data();
            main_session->safe_ptrace_load();
            main_session->do_cleanup();
            continue;
        }
        else if(operation.m_operation_enum == Operation::HOOK_TRIGGER){
            main_session->safe_trigger_hook();
            continue;
        }
    }
}
    



