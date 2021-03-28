#include <iostream>
#include <getopt.h>

const struct option longopts[] =
{
    {"icmp",   no_argument,        0, 'v'},
    {"arp",      no_argument,        0, 'h'},
    {0,0,0,0},
};

using namespace std;
int main(int argc, char **argv)
{
    
    
    
    int opt,a,b,c, d, e;
    while ((opt = getopt_long(argc,argv,"ip:tun:", longopts)) != EOF)
        switch(opt)
        {
            case 'i': a = 1; cout <<" i is enabled"<<a <<endl; break;
            case 'p': b = 1; cout << "value of p is"<< optarg <<endl ; break;
            case 't': c = 1; cout <<" t is enabled"<<c <<endl; break;
            case 'u': d = 1; cout <<" u is enabled"<<d <<endl; break;
            case 'n': e = 1; cout << "value of n is"<< optarg <<endl ; break;
            case '?': fprintf(stderr, "usuage is \n -a : for enabling a \n -b : for enabling b \n -c: <value> ");
            default: cout<<endl; exit(1);
        }

    return 0;
}