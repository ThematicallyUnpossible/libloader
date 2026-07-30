#include <iostream>
#include <optional>
#include "trigger.h"
#include <limits>
#include <type_traits>
#include <utility>
#include "unified_system.h"

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

    std::optional<LoaderSystem> syso_optional = LoaderSystem::initialize(argv[1], argv[2]);
    if(!syso_optional){
        std::cerr << "Error : failed to create system object\n";
        return 1;
    }

    syso_optional.value().fetch_data();
    syso_optional.value().ptrace_load();
}
    



