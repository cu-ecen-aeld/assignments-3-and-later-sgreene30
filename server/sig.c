#include <stdbool.h>
#include <signal.h>


bool caught_sigint = false;
bool caught_sigterm = false;

static void signal_handler(int sig_num)
{
    if(sig_num == SIGINT)
    {
        caught_sigint = true;
    }
    else if(sig_num == SIGTERM)
    {
        caught_sigterm = true;
    }
}

in main()
{
    struct sigaction new_action;
    bool success = true
}