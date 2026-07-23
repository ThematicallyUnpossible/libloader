#include <climits>
#include <iostream>
#include <optional>
#include "loader.h"
#include <type_traits>
#include <limits>


void refresh_cin(){
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

template<typename T>
    requires std::is_arithmetic_v<T>
    void prompt_mutate(std::string_view prefix, std::string_view line, T& target, T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max() ){
    
    std::cout << prefix;
        
    T temporary;
    while(true){
        std::cout << line;
        std::cin >> temporary;
        if(std::cin.fail()){
            refresh_cin();
            continue;
        }
        if(temporary < min || temporary > max){
            continue;
        }
        break;
    }
    target = temporary;
    return;
}

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
    std::cout << "program base : 0x" << std::hex <<  valid_object.m_base_address << std::dec <<   "\n";
    std::cout << "libc    base : 0x" << std::hex <<  valid_object.m_libc_address << std::dec <<   "\n";
    std::cout << "dlopen  addr : 0x" << std::hex <<  valid_object.m_dlopen_address << std::dec << "\n";

    int choice{};
    std::string modes = "1.Ptrace\n"
                        "2.ManualMap\n";
    prompt_mutate<int>(modes, "Select loading method : ", choice, 1, 2);
    if(choice == 1){
        bool load_success = load_library(valid_object, argv[2]);
        if(!load_success){
            return 1;
        }
    }
    else{
        std::cout << "wip\n";
    }


    

    




}
