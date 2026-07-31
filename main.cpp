#include <iostream>
#include <limits>
#include <type_traits>
#include "loader_system.h"

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

    std::optional<LoaderSystem> loader = LoaderSystem::initialize(argv[1], argv[2]);
    if(!loader){
        std::cerr << "Error : failed to create system object\n";
        return 1;
    }

    loader.value().fetch_data();
    loader.value().ptrace_load();
}
    



