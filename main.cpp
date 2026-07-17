#include <fstream>
#include <iostream>
#include <optional>
#include <filesystem>
#include <string>
#include <sys/ptrace.h>
#include <unistd.h>

struct ProcessInfo{
    std::string m_pid_string{};
    unsigned long long m_base_address{};
    unsigned long long m_libc_address{};
};

std::optional<ProcessInfo> get_process_info(std::string_view proc_name){

    for(const auto& dir : std::filesystem::directory_iterator{"/proc/"}){

        std::ifstream dir_comm(dir.path() / "comm");
        
        std::string dir_comm_string{};
        
        std::getline(dir_comm, dir_comm_string);

        if(dir_comm_string.find(proc_name) != std::string::npos){

            ProcessInfo temp{};

            temp.m_pid_string = dir.path().filename().string();

            std::ifstream maps_fstream("/proc/" + temp.m_pid_string + "/maps");

            std::string first_page{};

            std::getline(maps_fstream, first_page);

            std::size_t dash_iter = first_page.find('-');

            std::string address_string = first_page.substr(0, dash_iter);

            temp.m_base_address = std::stoull(address_string, nullptr, 16);

            std::string current_page{};
            while(getline(maps_fstream, current_page)){

                if(current_page.find("libc") != std::string::npos){
                    std::size_t current_dash_iter = current_page.find('-');
                    std::string libc_base{current_page.substr(0, current_dash_iter)};
                    unsigned long long libc_base_address = std::stoull(libc_base, nullptr,16);
                    temp.m_libc_address = libc_base_address;
                }


            }

            return temp;
        }
    }
    return std::nullopt;
}

int main(int argc, const char* argv[]){

    if(argc != 2){
        std::cerr << "Invalid usage. Expected : sudo ./libloader <process name>\n";
        return 1;
    }

    std::string_view target_string{argv[1]}; 

    auto info_optional = get_process_info(target_string);

    ProcessInfo valid_object{};

    if(info_optional){
        valid_object = std::move(info_optional.value());
    }

    std::cout << valid_object.m_pid_string << "\n";
    std::cout << "program base : 0x" << std::hex <<  valid_object.m_base_address << std::dec << "\n";
    std::cout << "libc    base : 0x" << std::hex <<  valid_object.m_libc_address << std::dec << "\n";



}
