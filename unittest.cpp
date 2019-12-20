
#include <gtest/gtest.h>
#include "packet_handler.hpp"

TEST(read_from_file, read_attack_file){
    packet_handle pkt_hnd = packet_handle();
    std::vector<std::pair<std::string, std::string> > attack_list;

    EXPECT_NE(attack_list, pkt_hnd.read_info_from_file((char*)"info"));
    EXPECT_EQ(attack_list, pkt_hnd.read_info_from_file((char*)"sadf"));
}


TEST(set_net_intf, make_virtual_list){
    packet_handle pkt_hnd = packet_handle();

    struct bpf_program fcode;
    char errbuf[256];
    pcap_if_t *alldevs, *d;
    pcap_t *adhandle;
    
    std::vector<char *> interface_list;
    interface_list.push_back((char*)"ens33");
    interface_list.push_back((char*)"lo");
    interface_list.push_back((char*)"virbr0");

    EXPECT_NE(interface_list,pkt_hnd.set_network_interface(adhandle, alldevs, d, errbuf));
}


TEST(select_interface_num, select_interface_number){
    packet_handle pkt_hnd = packet_handle();

    std::vector<char *> interface_list;
    interface_list.push_back((char*)"ens33");
    interface_list.push_back((char*)"lo");
    interface_list.push_back((char*)"virbr0");
    
    EXPECT_EQ(1, pkt_hnd.select_network_interface(interface_list));
}


TEST(valid_check_intf_num, check_valid_number){
    packet_handle pkt_hnd = packet_handle();

    std::vector<char *> interface_list;
    interface_list.push_back((char*)"ens33");
    interface_list.push_back((char*)"lo");
    interface_list.push_back((char*)"virbr0");
    
    EXPECT_EQ(true, pkt_hnd.valid_interface_number(1, interface_list));
    EXPECT_NE(true, pkt_hnd.valid_interface_number(11, interface_list));
}


TEST(test_get_interface_name, interface_name_ens33){
    packet_handle pkt_hnd = packet_handle();
    std::vector<char *> interface_list;
    interface_list.push_back((char*)"ens33");
    interface_list.push_back((char*)"lo");
    interface_list.push_back((char*)"virbr0");

    EXPECT_STREQ("ens33", pkt_hnd.get_interface_name(1, interface_list));
}


TEST(get_my_ip, interface_name_ens33){
    std::string temp_intf_name="ens33";

    packet_handle pkt_hnd = packet_handle();
    EXPECT_STREQ("192.168.218.131", pkt_hnd.set_my_ip((char*)"ens33"));
}


TEST(make_domain_test, domain_make){
    struct pcap_pkthdr header;
    const unsigned char *pkt_data=(const unsigned char*)"Æ<ÔBØót×(E<.þ¿Í'5(tBwwwgooglecom";

    for(int i=0;i<74;i++){
        printf("%2c ", pkt_data[i]);
        //printf("%.2x ", pkt_data[i]);
    }printf("\n");

    packet_handle pkt_hnd = packet_handle();
    EXPECT_STREQ("www.naver.com", pkt_hnd.make_domain(header, pkt_data));
}




int main(int argc, char **argv) {
    uid_t          user_id;
    struct passwd *user_pw;
    
    user_id = getuid();
    user_pw = getpwuid(user_id);
    
    if (user_pw->pw_uid != 0) {
        printf("Error: Permission denied\n", argv[0]);
        return 0;
    }
    
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}