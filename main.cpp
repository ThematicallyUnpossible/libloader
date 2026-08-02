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

    std::optional<Session>  main_session = Session::create_protected_environment(argv[1], argv[2]);
    if(!main_session){
        std::cerr << "Unable to create session,  double check arguments.\n";
        return 1;
    }
    main_session->safe_fetch_data();
    main_session->safe_ptrace_load();
    main_session->do_cleanup();
}
    



