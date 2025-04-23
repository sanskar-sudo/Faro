#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <map>
#include <sstream>
#include <fstream>
#include <cctype>

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

// Global configuration
struct Config {
    std::string interface;
    std::string read_file;
    std::string write_file;
    std::string filter_exp;
    bool verbose = false;
    bool hexdump = false;
    bool show_timestamp = true;
    bool show_ethernet = false;
    bool numeric = false;
    int packet_count = -1;
    int snaplen = 65535;
    int timeout_ms = 1000;
    bool promisc = true;
    pcap_dumper_t* dump_handle = nullptr;
};

Config config;

// Protocol mappings
const std::map<uint8_t, std::string> ip_protocols = {
    {IPPROTO_TCP, "TCP"},
    {IPPROTO_UDP, "UDP"},
    {IPPROTO_ICMP, "ICMP"},
    {IPPROTO_IGMP, "IGMP"},
    {IPPROTO_IP, "IP"},
    {IPPROTO_IPV6, "IPv6"},
    {IPPROTO_ESP, "ESP"},
    {IPPROTO_AH, "AH"},
    {IPPROTO_GRE, "GRE"}
};

const std::map<uint16_t, std::string> tcp_ports = {
    {20, "FTP-DATA"}, {21, "FTP"}, {22, "SSH"}, {23, "TELNET"},
    {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"},
    {143, "IMAP"}, {443, "HTTPS"}, {993, "IMAPS"}, {995, "POP3S"},
    {3306, "MYSQL"}, {3389, "RDP"}, {5432, "POSTGRESQL"}
};

// Helper functions
std::string format_mac(const u_char* mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(2) << (int)mac[0] << ":"
        << std::setw(2) << (int)mac[1] << ":"
        << std::setw(2) << (int)mac[2] << ":"
        << std::setw(2) << (int)mac[3] << ":"
        << std::setw(2) << (int)mac[4] << ":"
        << std::setw(2) << (int)mac[5];
    return oss.str();
}

std::string format_timestamp(const struct timeval& tv) {
    char buf[32];
    time_t sec = tv.tv_sec;
    struct tm* ptm = localtime(&sec);
    strftime(buf, sizeof(buf), "%H:%M:%S", ptm);
    
    std::ostringstream oss;
    oss << buf << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;
    return oss.str();
}

std::string port_to_service(uint16_t port, bool is_tcp) {
    if (config.numeric) return std::to_string(port);
    
    auto it = tcp_ports.find(port);
    if (it != tcp_ports.end()) {
        return it->second + "(" + std::to_string(port) + ")";
    }
    return std::to_string(port);
}

void hexdump(const u_char* data, size_t length) {
    std::cout << COLOR_CYAN << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; i += 16) {
        // Print offset
        std::cout << "0x" << std::setw(4) << i << ":  ";
        
        // Print hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                std::cout << std::setw(2) << (int)data[i + j] << " ";
            } else {
                std::cout << "   ";
            }
            if (j == 7) std::cout << " ";
        }
        
        std::cout << " ";
        
        // Print ASCII
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                unsigned char c = data[i + j];
                if (isprint(c) && !isspace(c)) {
                    std::cout << c;
                } else {
                    std::cout << ".";
                }
            }
        }
        
        std::cout << std::endl;
    }
    std::cout << COLOR_RESET << std::dec;
}

void print_ethernet_header(const struct ether_header* eth) {
    std::cout << COLOR_MAGENTA << "Ethernet: " << COLOR_YELLOW << format_mac(eth->ether_shost) 
              << COLOR_MAGENTA << " -> " << COLOR_YELLOW << format_mac(eth->ether_dhost)
              << COLOR_MAGENTA << " type 0x" << std::hex << ntohs(eth->ether_type) << std::dec << COLOR_RESET << "\n";
}

void print_ip_header(const struct ip* iph) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);

    std::string protocol = "Unknown";
    auto it = ip_protocols.find(iph->ip_p);
    if (it != ip_protocols.end()) protocol = it->second;

    std::cout << COLOR_BLUE << "IP: " << COLOR_GREEN << src_ip << COLOR_BLUE << " -> " << COLOR_GREEN << dst_ip 
              << COLOR_BLUE << " ttl=" << (int)iph->ip_ttl
              << " proto=" << protocol << "(" << (int)iph->ip_p << ")"
              << " len=" << ntohs(iph->ip_len) << COLOR_RESET << "\n";
}

void print_tcp_header(const struct tcphdr* tcph) {
    std::cout << COLOR_CYAN << "TCP: " << COLOR_YELLOW << port_to_service(ntohs(tcph->th_sport), true)
              << COLOR_CYAN << " -> " << COLOR_YELLOW << port_to_service(ntohs(tcph->th_dport), true)
              << COLOR_CYAN << " flags=";
    
    if (tcph->th_flags & TH_FIN) std::cout << "FIN ";
    if (tcph->th_flags & TH_SYN) std::cout << "SYN ";
    if (tcph->th_flags & TH_RST) std::cout << "RST ";
    if (tcph->th_flags & TH_PUSH) std::cout << "PSH ";
    if (tcph->th_flags & TH_ACK) std::cout << "ACK ";
    if (tcph->th_flags & TH_URG) std::cout << "URG ";
    
    std::cout << "seq=" << ntohl(tcph->th_seq)
              << " ack=" << ntohl(tcph->th_ack)
              << " win=" << ntohs(tcph->th_win)
              << " urp=" << ntohs(tcph->th_urp) << COLOR_RESET << "\n";
}

void print_udp_header(const struct udphdr* udph) {
    std::cout << COLOR_GREEN << "UDP: " << COLOR_YELLOW << port_to_service(ntohs(udph->uh_sport), false)
              << COLOR_GREEN << " -> " << COLOR_YELLOW << port_to_service(ntohs(udph->uh_dport), false)
              << COLOR_GREEN << " len=" << ntohs(udph->uh_ulen) << COLOR_RESET << "\n";
}

void print_icmp_header(const struct icmp* icmph) {
    std::cout << COLOR_RED << "ICMP: type=" << (int)icmph->icmp_type 
              << " code=" << (int)icmph->icmp_code
              << " id=" << ntohs(icmph->icmp_id)
              << " seq=" << ntohs(icmph->icmp_seq) << COLOR_RESET << "\n";
}

void process_packet(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    Config* cfg = (Config*)user;
    static int packet_num = 1;
    
    if (cfg->packet_count > 0 && packet_num > cfg->packet_count) {
        pcap_breakloop((pcap_t*)user);
        return;
    }

    // Save packet to file if dump handle is open
    if (cfg->dump_handle) {
        pcap_dump((u_char*)cfg->dump_handle, pkthdr, packet);
    }

    if (cfg->show_timestamp) {
        std::cout << COLOR_WHITE << format_timestamp(pkthdr->ts) << " ";
    }
    std::cout << COLOR_BOLD << "Packet #" << packet_num << COLOR_RESET << ", len=" << pkthdr->len << "\n";

    // Ethernet header
    const struct ether_header* eth = (struct ether_header*)packet;
    if (cfg->show_ethernet) {
        print_ethernet_header(eth);
    }

    // Check for IP packet
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        const struct ip* iph = (struct ip*)(packet + sizeof(struct ether_header));
        print_ip_header(iph);

        int ip_header_len = iph->ip_hl * 4;
        const u_char* transport = packet + sizeof(struct ether_header) + ip_header_len;

        switch (iph->ip_p) {
            case IPPROTO_TCP: {
                const struct tcphdr* tcph = (struct tcphdr*)transport;
                print_tcp_header(tcph);
                break;
            }
            case IPPROTO_UDP: {
                const struct udphdr* udph = (struct udphdr*)transport;
                print_udp_header(udph);
                break;
            }
            case IPPROTO_ICMP: {
                const struct icmp* icmph = (struct icmp*)transport;
                print_icmp_header(icmph);
                break;
            }
        }
    }

    if (cfg->hexdump) {
        hexdump(packet, pkthdr->caplen);
    }

    std::cout << std::endl;
    packet_num++;
}

void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " [options]\n"
              << "Options:\n"
              << "  -i <interface>  Listen on specified interface\n"
              << "  -r <file>       Read packets from pcap file\n"
              << "  -w <file>       Write packets to pcap file\n"
              << "  -c <count>      Stop after receiving count packets\n"
              << "  -s <snaplen>   Set snapshot length (default: 65535)\n"
              << "  -f <filter>     Use filter expression\n"
              << "  -v              Verbose output\n"
              << "  -x              Hex dump of packet (with ASCII)\n"
              << "  -e              Show Ethernet header\n"
              << "  -t              Don't print timestamp\n"
              << "  -n              Numeric output only (no DNS/port resolution)\n"
              << "  -p              Don't put interface in promiscuous mode\n"
              << "  -l              List available interfaces\n"
              << "  -h              Show this help message\n";
}

void list_interfaces() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    std::cout << "Available interfaces:\n";
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << "  " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        std::cout << "\n";
    }

    pcap_freealldevs(alldevs);
}

int main(int argc, char* argv[]) {
    // Parse command line options
    int opt;
    while ((opt = getopt(argc, argv, "i:r:w:c:s:f:vxetnphl")) != -1) {
        switch (opt) {
            case 'i':
                config.interface = optarg;
                break;
            case 'r':
                config.read_file = optarg;
                break;
            case 'w':
                config.write_file = optarg;
                break;
            case 'c':
                config.packet_count = std::stoi(optarg);
                break;
            case 's':
                config.snaplen = std::stoi(optarg);
                break;
            case 'f':
                config.filter_exp = optarg;
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'x':
                config.hexdump = true;
                break;
            case 'e':
                config.show_ethernet = true;
                break;
            case 't':
                config.show_timestamp = false;
                break;
            case 'n':
                config.numeric = true;
                break;
            case 'p':
                config.promisc = false;
                break;
            case 'l':
                list_interfaces();
                return 0;
            case 'h':
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open either live capture or file
    if (!config.read_file.empty()) {
        // Verify file exists and has content first
        std::ifstream test_file(config.read_file, std::ios::binary);
        if (!test_file.good()) {
            std::cerr << COLOR_RED << "Error: File '" << config.read_file << "' doesn't exist or isn't readable" << COLOR_RESET << "\n";
            return 2;
        }
        
        test_file.seekg(0, std::ios::end);
        size_t size = test_file.tellg();
        test_file.close();
        
        if (size < 24) {  // Minimum pcap file size
            std::cerr << COLOR_RED << "Error: File '" << config.read_file << "' is too small (" << size 
                      << " bytes) to be a valid pcap file" << COLOR_RESET << "\n";
            return 2;
        }

        handle = pcap_open_offline(config.read_file.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << COLOR_RED << "Couldn't open pcap file '" << config.read_file << "': " << errbuf << COLOR_RESET << std::endl;
            return 2;
        }
    } else {
        // If no interface specified, get the default one
        if (config.interface.empty()) {
            pcap_if_t* alldevs;
            if (pcap_findalldevs(&alldevs, errbuf) == -1) {
                std::cerr << COLOR_RED << "Couldn't find any devices: " << errbuf << COLOR_RESET << std::endl;
                return 2;
            }
            if (alldevs == nullptr) {
                std::cerr << COLOR_RED << "No network devices found" << COLOR_RESET << std::endl;
                return 2;
            }
            config.interface = alldevs->name;
            pcap_freealldevs(alldevs);
        }

        handle = pcap_open_live(config.interface.c_str(), config.snaplen, 
                               config.promisc, config.timeout_ms, errbuf);
        if (handle == nullptr) {
            std::cerr << COLOR_RED << "Couldn't open device " << config.interface << ": " << errbuf << COLOR_RESET << std::endl;
            return 2;
        }
    }

    // Open dump file if specified
    if (!config.write_file.empty()) {
        config.dump_handle = pcap_dump_open(handle, config.write_file.c_str());
        if (config.dump_handle == nullptr) {
            std::cerr << COLOR_RED << "Couldn't open output file: " << pcap_geterr(handle) << COLOR_RESET << std::endl;
            pcap_close(handle);
            return 2;
        }
    }

    // Set filter if specified
    if (!config.filter_exp.empty()) {
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;

        if (pcap_lookupnet(config.interface.c_str(), &net, &mask, errbuf) == -1) {
            std::cerr << COLOR_YELLOW << "Couldn't get netmask for device " << config.interface << ": " << errbuf << COLOR_RESET << std::endl;
            net = 0;
            mask = 0;
        }

        if (pcap_compile(handle, &fp, config.filter_exp.c_str(), 0, net) == -1) {
            std::cerr << COLOR_RED << "Couldn't parse filter " << config.filter_exp << ": " << pcap_geterr(handle) << COLOR_RESET << std::endl;
            pcap_close(handle);
            if (config.dump_handle) pcap_dump_close(config.dump_handle);
            return 2;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << COLOR_RED << "Couldn't install filter " << config.filter_exp << ": " << pcap_geterr(handle) << COLOR_RESET << std::endl;
            pcap_close(handle);
            if (config.dump_handle) pcap_dump_close(config.dump_handle);
            return 2;
        }

        pcap_freecode(&fp);
    }

    // Print capture info
    std::cout << COLOR_BOLD << "Capturing on ";
    if (!config.read_file.empty()) {
        std::cout << "file " << config.read_file;
    } else {
        std::cout << "interface " << config.interface;
    }
    
    if (!config.filter_exp.empty()) {
        std::cout << ", filter: " << config.filter_exp;
    }
    
    if (config.packet_count > 0) {
        std::cout << ", capturing " << config.packet_count << " packets";
    }
    
    std::cout << COLOR_RESET << std::endl;

    // Start capturing packets
    pcap_loop(handle, config.packet_count, process_packet, (u_char*)&config);

    // Close handles
    pcap_close(handle);
    if (config.dump_handle) {
        pcap_dump_close(config.dump_handle);
    }

    return 0;
}
