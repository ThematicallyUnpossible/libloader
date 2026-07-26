#ifndef TRIGGER 
#define TRIGGER
#include "loader.h"
#include <cstddef>
#include <fcntl.h>
#include <string>

struct Target{
    std::string lib_name{};
    unsigned long long hook_fcn_offset{};
    unsigned long long original_fcn_offset{};
};

inline bool trigger_hook(ProcessInfo& minfo, Target& target){
    
    //figure out the base of the hook function
    //firstly we have to find the location of the lib inside the target.

    std::ifstream maps_fstream("/proc/"+minfo.m_pid_string+"/maps");
    std::string current_page{};

    unsigned long long lib_rxp_base{};
    while(std::getline(maps_fstream, current_page)){

        std::size_t dash_index = current_page.find('-');
        std::size_t space_index = current_page.find(' ');
        if(dash_index == std::string::npos || space_index == std::string::npos){
            std::cerr << "~dash / space index isnt found, skipping current page.\n";
            continue;
        }
        std::string temporary_address_string{};
        if(current_page.find(target.lib_name) != std::string::npos){
            temporary_address_string = current_page.substr(0, dash_index);
            std::cout << "*Found lib's base at 0x"<< temporary_address_string << '\n';    
            
            try{ 
                lib_rxp_base = std::stoull(temporary_address_string, nullptr, 16);
            }
            catch(...){
                std::cerr << "~Failed to convert string to ull\n";
                return false;
            }
            break;
        }
        
    }
    maps_fstream.close();

    if(!lib_rxp_base){
        std::cerr << "~Lib not found. Is it loaded?";
        return false;
    }

    
    unsigned long long original_function_address = minfo.m_base_address + target.original_fcn_offset;
    unsigned long long hooked_function_address = lib_rxp_base + target.hook_fcn_offset;

    //calculation complete, ill try to write the instruction directly into memory stream

    uint8_t bytes_to_write[14];
    bytes_to_write[0] = 0xFF;
    bytes_to_write[1] = 0x25;
    bytes_to_write[2] = 0x00;
    bytes_to_write[3] = 0x00;
    bytes_to_write[4] = 0x00;
    bytes_to_write[5] = 0x00;

    memcpy(&bytes_to_write[6], &hooked_function_address, 8);

    //opening the file to write at the original function byte stream.
    std::string path_to_mem{"/proc/"+minfo.m_pid_string+"/mem"};
    int target_fd = open(path_to_mem.c_str(), O_WRONLY);
    if(target_fd < 0){
        std::cerr << "~Failed to open " + path_to_mem;
        return false;
    }

    lseek(target_fd, original_function_address, SEEK_SET);
    ssize_t byte_written = write(target_fd, bytes_to_write, 14);
    close(target_fd);

    std::cout << "*Function HOOKED.\n";
    return true;
}

#endif