#ifndef UTILITY
#define UTILITY

#include <cstddef>
#include <iostream>
#include <limits>
#include <type_traits>
#include <vector>

inline void refresh_cin(){
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

inline unsigned long long prompt_offset(std::string_view prompt){
    std::cout << prompt;
    std::string original_offset_string{};
    std::cin >>  original_offset_string;

    return std::stoull(original_offset_string, nullptr, 16);
}

template<typename T>
    requires std::is_arithmetic_v<T>
    inline void prompt_mutate(std::string_view prefix, std::string_view line, T& target, T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max() ){
    
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

enum class Operation :  std::size_t{
    PTRACE_LOAD,
    HOOK_TRIGGER,
};

struct ChoiceContainer{
    std::string m_operation_string{};
    Operation m_operation_enum{};
};

inline ChoiceContainer get_choice(){
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

#endif