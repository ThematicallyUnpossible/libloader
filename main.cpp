#include <iostream>
#include <optional>
#include "loader.h"


int main(int argc, const char* argv[]){

    if(argc != 3){
        std::cerr << "Invalid usage. Expected : sudo ./libloader <process name> <lib_path>\n";
        return 1;
    }

    std::string_view target_string{argv[1]}; 

    auto info_optional = get_process_info(target_string);

    ProcessInfo valid_object{};

    if(info_optional){
        valid_object = std::move(info_optional.value());
    }

    std::cout << valid_object.m_pid_string << "\n";
    std::cout << "program base : 0x" << std::hex <<  valid_object.m_base_address << std::dec << "\n";
    std::cout << "libc    base : 0x" << std::hex <<  valid_object.m_libc_address << std::dec << "\n";
    std::cout << "dlopen  addr : 0x" << std::hex <<  valid_object.m_dlopen_address << std::dec << "\n";

    bool load_success = load_library(valid_object, argv[2]);
    if(!load_success){
        return 1;
    }

    




}
