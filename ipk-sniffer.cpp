#include <iostream>
#include <getopt.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string>
#include <sys/time.h>
#include <math.h>
#include <arpa/inet.h>
#include <iomanip>
#include <map>
#include <boost/algorithm/string.hpp>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

	/* IP header */
struct sniff_ipv4 {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct sniff_ipv6{
    __int32_t prefix;
    u_int16_t payload_len;
    u_int8_t next_header;
    u_int8_t hop_limit;
    in6_addr source;
    in6_addr destination;
};

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
        u_short th_sport;	/* source port */
        u_short th_dport;	/* destination port */
        tcp_seq th_seq;		/* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
        u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
};

struct sniff_udp {
    u_int16_t sport;
    u_int16_t dport;
    u_int16_t len;
    u_int16_t checksum;
    u_int32_t data;
};

class Restrictions {
    public:
        char* device = NULL;
        int numof_packets = 1;
        int port = -1;
        std::string filter_exp = "";
        bool print_or = false;
        std::map<std::string, bool> possible_packets {
            {"ALL", true},
            {"TCP", false},
            {"UDP", false},
            {"ICMP", false},
            {"ARP", false}
        };

        void set_possible_packets(std::string packet){
            possible_packets["ALL"] = false;
            possible_packets[packet] = true;
        }

        void set_all_possible_packets(){
            possible_packets["TCP"] = true;
            possible_packets["UDP"] = true;
            possible_packets["ICMP"] = true;
            possible_packets["ARP"] = true;
        }

        void set_port(std::string port_num){
            filter_exp = "port ";
            filter_exp = filter_exp.append(port_num);
        }

        void build_filter(){
            if(possible_packets["TCP"])
                append_to_filter("tcp");
            if(possible_packets["UDP"])
                append_to_filter("udp");
            if(possible_packets["ICMP"])
                append_to_filter("icmp");
            if(possible_packets["ARP"])
                append_to_filter("arp");     
        }

        void append_to_filter(std::string protocol){
            if(!print_or && filter_exp!=""){
                filter_exp = filter_exp.append(" && ");
            } else if(print_or){
                filter_exp = filter_exp.append(" || ");
            }
            filter_exp = filter_exp.append(protocol);
            print_or = true;
        }
} restr;

void print_time(struct timeval timestamp){
    char buff[26];
    char zone[5];
    int millisec;
    struct tm* tm_info;


    millisec = lrint(timestamp.tv_usec/1000.0);

    tm_info = localtime(&timestamp.tv_sec);

    strftime(buff, 26, "%Y-%m-%dT%H:%M:%S", tm_info);
    printf("%s.%03d", buff, millisec);
    strftime(buff, 26, "%z", tm_info);
    printf("+%c%c:00 ", buff[1], buff[2]);
}

//  Uniform way of printing all packets.
//  Using one main loop for 16 bytes, then two loops inside.
//  One for hexadecimal representation, one for ASCII representation.
void print_packet(const u_char* packet, int packet_len){
    using namespace std;
    cout<< endl;
    for(int i = 0; i< ((packet_len+16-1)/16); i++){                                     //rounding up division
        cout << "0x" << setw(4) << setfill('0') << hex << i*16 << ":  ";
        for( int j = 0; j<16; j++){
            if(j == 8){
                cout << " ";
            }
            if(i*16+j >= packet_len){
                cout << "   ";
            } else {
                cout << setw(2) << setfill('0') <<hex << (int)packet[i*16+j] << " ";
            }
        } 

        cout << " ";

        for( int j = 0; j<16; j++){
            if(j == 8){
                cout << " ";
            }
            if(i*16+j >= packet_len){
                cout << " ";
            } else {
                if(isprint(packet[i*16+j])){
                    cout << packet[i*16+j];
                } else{
                    cout << ".";
                }
            }
        }
        cout << endl;
    }
    cout << endl;
}

void print_mac_address(const u_char* addr){
    using namespace std;
    cout << setw(2) << setfill('0') << hex << (int)addr[0] << ":";
    cout << setw(2) << setfill('0') << hex << (int)addr[1] << ":";
    cout << setw(2) << setfill('0') << hex << (int)addr[2] << ":";
    cout << setw(2) << setfill('0') << hex << (int)addr[3] << ":";
    cout << setw(2) << setfill('0') << hex << (int)addr[4] << ":";
    cout << setw(2) << setfill('0') << hex << (int)addr[5]; 
}

void arp_packet(const struct sniff_ethernet *ethernet, const struct pcap_pkthdr* pkthdr,const u_char* packet){
    print_time(pkthdr->ts);
    using namespace std;
    print_mac_address(ethernet->ether_shost);
    cout << " > ";
    print_mac_address(ethernet->ether_dhost);
    cout << ", ";
    printf("length %d bytes\n", pkthdr->caplen);

    print_packet(packet, pkthdr->caplen);
}

std::string ready_port_output(int port){
    std::string appendee = " : ";
    return appendee.append(std::to_string(port));
}

void ipv4_packet(const struct pcap_pkthdr* pkthdr,const u_char* packet){
#define SIZE_ETHERNET 14
	const struct sniff_ipv4 *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

    std::string sport= "";
    std::string dport= "";

	ip = (struct sniff_ipv4*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

    if(ip->ip_p == '\x11' && restr.possible_packets["UDP"]){
        const struct sniff_udp *udp;

        udp = (struct sniff_udp*)(packet+SIZE_ETHERNET+size_ip);
        sport = ready_port_output(ntohs(udp->sport));
        dport = ready_port_output(ntohs(udp->dport));
    } else if (ip->ip_p == '\x06' && restr.possible_packets["TCP"]){
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        sport = ready_port_output(ntohs(tcp->th_sport));
        dport = ready_port_output(ntohs(tcp->th_dport));  
    } else if (ip->ip_p == '\x01' && restr.possible_packets["ICMP"]){
    } else{
        if(!restr.possible_packets["ALL"])
            return;
    }

    print_time(pkthdr->ts);
    printf("%s%s ", inet_ntoa(ip->ip_src), sport.c_str());
    printf("> %s%s, ", inet_ntoa(ip->ip_dst), dport.c_str());
    printf("length %d bytes\n", pkthdr->caplen);

    print_packet(packet, pkthdr->caplen);  
}

void ipv6_packet(const struct pcap_pkthdr* pkthdr,const u_char* packet){
#define SIZE_IPv6 40

    const struct sniff_ipv6 *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

    std::string sport= "";
    std::string dport= "";

    ip = (struct sniff_ipv6*)(packet + SIZE_ETHERNET);

    if(ip->next_header == '\x11' && restr.possible_packets["UDP"]){
        const struct sniff_udp *udp;

        udp = (struct sniff_udp*)(packet+SIZE_ETHERNET+SIZE_IPv6);
        sport = ready_port_output(ntohs(udp->sport));
        dport = ready_port_output(ntohs(udp->dport));
    } else if (ip->next_header == '\x06' && restr.possible_packets["TCP"]){
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + SIZE_IPv6);
        sport = ready_port_output(ntohs(tcp->th_sport));
        dport = ready_port_output(ntohs(tcp->th_dport));  
    } else if (ip->next_header == '\x01' && restr.possible_packets["ICMP"]){
    } else{
        if(!restr.possible_packets["ALL"])
            return;
    }

    char buf6[INET6_ADDRSTRLEN];
    print_time(pkthdr->ts);
    printf("%s%s ", inet_ntop(AF_INET6, &ip->source,buf6, sizeof(buf6)), sport.c_str());
    printf("> %s%s, ", inet_ntop(AF_INET6, &ip->destination,buf6, sizeof(buf6)), dport.c_str());
    printf("length %d bytes\n", pkthdr->caplen);

    print_packet(packet, pkthdr->caplen); 
}

void get_ethernet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet; /* The ethernet header */

	ethernet = (struct sniff_ethernet*)(packet);
    
    if(htons(ethernet->ether_type) == 0x0800){
        if(restr.possible_packets["ICMP"] || restr.possible_packets["TCP"] || restr.possible_packets["UDP"])
            ipv4_packet(pkthdr, packet);
    } else if(htons(ethernet->ether_type) == 0x86dd){
        if(restr.possible_packets["ICMP"] || restr.possible_packets["TCP"] || restr.possible_packets["UDP"])
            ipv6_packet(pkthdr, packet);
    }else if(htons(ethernet->ether_type) == 0x0806){
        if(restr.possible_packets["ARP"]){
            arp_packet(ethernet, pkthdr, packet);
        }
    } else if(restr.possible_packets["ALL"]){
        print_mac_address(ethernet->ether_shost);
        std::cout << " > ";
        print_mac_address(ethernet->ether_dhost);
        std::cout << ", ";
        printf("length %d bytes\n", pkthdr->caplen);

        print_packet(packet, pkthdr->caplen);
    }

}


char *interface_option(char *dev){
    pcap_if_t *devices = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&devices, errbuf) != 0){
        fprintf(stderr, "Couldn't find any devices: %s\n", errbuf);
        exit(2);
    }

    while (devices!=NULL){
        if(dev == NULL){
            std::cout << devices->name << std::endl;
        } else if (!strcmp(dev, devices->name)){
            return devices->name;
        }
        devices = devices->next;
    }
    if(dev != NULL){
        fprintf(stderr, "Invalid interface.\n");
        exit(1);
    }
    exit(0);
    
}

const struct option longopts[] =
{
    {"icmp",        no_argument,          0,   'x'},
    {"arp",         no_argument,          0,   'y'},
    {"tcp",         no_argument,          0,   't'},
    {"udp",         no_argument,          0,   'u'},
    {"interface",   required_argument,    0,   'f'},
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
    exit(1);
}

//  Parsing Command Line arguments and setting restr options.
void set_restrictions(int argc, char **argv){
    int opt,index;
    opterr = 0;
    while ((opt = getopt_long(argc,argv,"i:p:tun:h", longopts, &index)) != EOF)
    {
        switch(opt)
        {
            case 'h': CLI_arg_usage();
            case 'i':   if(optarg!=NULL){
                            restr.device = optarg;
                        }
                        break;                
            case 'f':   if(optarg!=NULL){
                            restr.device = optarg;
                        }
                        break;
            case 'p': restr.set_port(optarg); break;
            case 't': restr.set_possible_packets("TCP"); break;
            case 'u': restr.set_possible_packets("UDP"); break;
            case 'n': restr.numof_packets = atoi(optarg); break;
            case 'x': restr.set_possible_packets("ICMP"); break;
            case 'y': restr.set_possible_packets("ARP"); break;
            case '?':   if(optopt == 'i'){
                            continue;
                        }
            default: CLI_arg_usage();
        }
    }
    if(restr.possible_packets["ALL"])
    {
        restr.set_all_possible_packets();
    }
    restr.build_filter();
}

using namespace std;
int main(int argc, char **argv)
{
    pcap_t *handle;		            /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		    /* The compiled filter expression */
    bpf_u_int32 mask;		        /* The netmask of our sniffing device */
    bpf_u_int32 net;		        /* The IP of our sniffing device */
    struct pcap_pkthdr header;	    /* The header that pcap gives us */
    const u_char *packet;		    /* The actual packet */
    
    set_restrictions(argc, argv);

    std::cout << restr.filter_exp << std::endl;
    
    restr.device = interface_option(restr.device);
    if (restr.device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", restr.device);
	
    if (pcap_lookupnet(restr.device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", restr.device);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(restr.device, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", restr.device, errbuf);
        return(2);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", restr.device);
		return(2);
	}

    if (pcap_compile(handle, &fp, restr.filter_exp.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", restr.filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", restr.filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, (int)restr.numof_packets, get_ethernet, NULL);

    return 0;
}