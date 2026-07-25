#ifndef TRIGGER 
#define TRIGGER
#include "loader.h"

struct Target{
    unsigned long long hook_offset{};
    unsigned long long function_offset{};
};

inline void trigger_hook(ProcessInfo& minfo, Target& tinfo){
    char bytes_to_write[14];
    bytes_to_write[0] = 0xFF;
    bytes_to_write[1] = 0x25;
    bytes_to_write[2] = 0x00;
    bytes_to_write[4] = 0x00;
    bytes_to_write[5] = 0x00;
    bytes_to_write[6] = 0x00; 
}

#endif