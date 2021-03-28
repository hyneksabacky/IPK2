#include <iostream>
#include <getopt.h>

const struct option longopts[] =
{
    {"icmp",        no_argument,          0,   'x'},
    {"arp",         no_argument,          0,   'y'},
    {"tcp",         no_argument,          0,   't'},
    {"udp",         no_argument,          0,   'u'},
    {"interface",   optional_argument,    0,   'i'},
    {"help",        no_argument,          0,   'h'},
    {0,0,0,0},
};

void CLI_arg_usage(){
    fprintf(stderr,
    "\nusuage is: \n\n" 
    "./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"
    "\n"
    "interface | i : <value>  - for selecting interface.\n" 
    "          | p : <value>  - number of port (if not specified, all ports). \n" 
    "      tcp | t : <switch> - tcp packets only. \n"
    "      udp | u : <switch> - udp packets only. \n"
    "      arp |   : <switch> - only ARP frames.\n"
    "     icmp |   : <switch> - only ICMPv4 and ICMPv6 packets. \n"
    "          | n : <value>  - number of packets to be shown (default is 1).\n"
    "     help | h : <help>   - show this message. \n\n"
    );
}

using namespace std;
int main(int argc, char **argv)
{
    
    int opt,a,b,c, d, e, index;
    while ((opt = getopt_long(argc,argv,"i:p:tun:h", longopts, &index)) != EOF)
        switch(opt)
        {
            case 'h': CLI_arg_usage(); exit(1);
            case 'i': a = 1; cout <<"value of i is "<< optarg <<endl ; break;
            case 'p': b = 1; cout << "value of p is "<< optarg <<endl ; break;
            case 't': c = 1; cout <<" t is enabled"<<c <<endl; break;
            case 'u': d = 1; cout <<" u is enabled"<<d <<endl; break;
            case 'n': e = 1; cout << "value of n is "<< optarg <<endl ; break;
            case 'x': e = 1; cout << "icmp is enabled"<<endl ; break;
            case 'y': e = 1; cout << "arp is enabled"<<endl ; break;
            case '?': CLI_arg_usage();
            default: cout<<endl; exit(1);
        }

    return 0;
}