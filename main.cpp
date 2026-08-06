#include <iostream>
#include "loader_system.h"
#include "utility.h"


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

    while(true){
        auto operation = get_choice();
        if(operation.m_operation_enum == Operation::PTRACE_LOAD){
            main_session->safe_fetch_data();
            main_session->safe_ptrace_load();
            main_session->do_cleanup();
            continue;
        }
        else if(operation.m_operation_enum == Operation::HOOK_TRIGGER){
            main_session->safe_trigger_hook();
            continue;
        }
    }
}
    



