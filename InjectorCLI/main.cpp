#include <iostream>
#include <string>
#include <vector>
#include <cxxopts.hpp>
using namespace std;


int main(int argc, char* argv[])
{
    string yaml_config;
    string process_name;
    int pid;
    string new_process_path;
    vector<string> new_process_command_line;

    cxxopts::Options options(argv[0], "A command line interface for Injector");
    options.set_width(100);

    options.add_options()
        ( "c,config",    "configuration file with yaml format", cxxopts::value<string>(yaml_config)->default_value("scylla.yaml"),  "<path>" )
        ( "p,pid",       "pid of target process",  cxxopts::value<int>(pid),  "<pid>" )
        ( "name",        "process name of target process", cxxopts::value<string>(process_name), "<name>" )
        ( "new",         "new process path", cxxopts::value<string>(new_process_path), "<path>" )
        ( "h,help",      "print help");

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    } catch (std::exception e) {
        cout << "bad arguments" << endl;
        cout << options.help() << endl;
        return 1;
    }

    if (result.count("help")) {
        cout << options.help() << endl;
        return 0;
    }
}