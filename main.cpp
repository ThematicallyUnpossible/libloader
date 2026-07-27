#include <iostream>
#include <optional>
#include "loader.h"
#include "trigger.h"
#include <limits>
#include <type_traits>
#include <utility>

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

Target make_target(){
    std::cout << "?Enter original function offset : ";
    std::string original_string{};
    refresh_cin();
    std::getline(std::cin, original_string);
    unsigned long long original_offset_ull{};
    original_offset_ull = std::stoull(original_string, nullptr, 16);

    std::cout << "?Enter hook function offset : ";
    std::string hook_string{};
    std::getline(std::cin, hook_string);
    unsigned long long hook_offset_ull{};
    hook_offset_ull = std::stoull(hook_string, nullptr, 16);

    std::cout << "?Enter lib name : ";
    std::string lib_string{};
    std::getline(std::cin, lib_string);

    return {.lib_name = std::move(lib_string), .hook_fcn_offset = hook_offset_ull, .original_fcn_offset = original_offset_ull};
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

    while(true){
        int choice{};
        std::string modes = "1.Ptrace\n"
                            "2.ManualMap\n"
                            "3.Trigger lib\n";
        prompt_mutate<int>(modes, "Select loading method : ", choice, 1, 3);

        if(choice == 1){
            bool load_success = load_library_ptrace(valid_object, argv[2]);
            if(!load_success){
                return 1;
            }
        }
        else if (choice == 2){
            bool load_success = load_library_manualmap(valid_object, argv[2]);
            if(!load_success){
                return 1;
            }
        }
        else if(choice == 3){
            Target target = make_target();
            trigger_hook(valid_object, target);
        }
    }
    


    

    




}
