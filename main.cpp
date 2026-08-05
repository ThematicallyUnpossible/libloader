#include <cstddef>
#include <iostream>
#include <limits>
#include <type_traits>
#include "loader_system.h"
void refresh_cin(){
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

enum class Operation :  std::size_t{
    PTRACE_LOAD,
    HOOK_TRIGGER,
};

struct ChoiceContainer{
    std::string m_operation_string{};
    Operation m_operation_enum{};
};



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

ChoiceContainer get_choice(){
    const std::vector<ChoiceContainer> choice_list{
        {"Load with ptrace", Operation::PTRACE_LOAD},
        {"Trigger hook function", Operation::HOOK_TRIGGER}
    };
    auto print_list = [&choice_list](){
        for(const auto& obj : choice_list){
            std::size_t index = static_cast<std::size_t>(obj.m_operation_enum);
            std::cout << index << ". " << choice_list[index].m_operation_string << "\n";
        }
    };
    const std::size_t choice_min{0};
    const std::size_t choice_max{(choice_list.size()-1)};
    
    print_list();
    while(true){
        std::size_t choice{};
        prompt_mutate<std::size_t>("", "Type your operation choice: ", choice, choice_min, choice_max);
        return choice_list[choice];
    }
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
    auto operation = get_choice();
    if(operation.m_operation_enum == Operation::PTRACE_LOAD){
        main_session->safe_fetch_data();
        main_session->safe_ptrace_load();
        main_session->do_cleanup();
    }
    
    main_session->safe_trigger_hook("libfcnhook.so");
}
    



