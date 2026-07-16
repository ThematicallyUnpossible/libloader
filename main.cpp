#include <fstream>
#include <iostream>
#include <optional>
#include <filesystem>

struct ProcessInfo{
    std::string pid{};
};

std::optional<ProcessInfo> get_pid_string(std::string_view proc_name){
    
    ProcessInfo temp{};

    for(const auto& dir : std::filesystem::directory_iterator{"/proc/"}){

        std::ifstream dir_comm(dir.path() / "comm");
        
        std::string dir_comm_string{};
        
        std::getline(dir_comm, dir_comm_string);

        if(dir_comm_string.find(proc_name) != std::string::npos){
            temp.pid = dir.path().filename().string();
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
    auto x = get_pid_string(target_string);
    ProcessInfo valid_object{};
    if(x){
        valid_object = std::move(x.value());
    }

    std::cout << valid_object.pid << "\n";

}
