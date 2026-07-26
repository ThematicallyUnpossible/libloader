#ifndef TRIGGER 
#define TRIGGER
#include "loader.h"
#include <string>


inline void trigger_hook(ProcessInfo& minfo){
    
    //figure out the base of the hook function
    //firstly we have to find the location of the lib inside the target.

    std::ifstream maps_fstream("/proc/"+minfo.m_pid_string+"/maps");
    std::string current_page{};
    while(std::getline(maps_fstream, current_page)){
        std::cout << current_page << '\n';
    }

    
}

#endif