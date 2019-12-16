
#include <gtest/gtest.h>
#include "packet_handler.hpp"

TEST(aaaa, aaaa){
    char file_name[256] = "info";
    
    packet_handle pkt_hnd = packet_handle();
    std::vector<std::pair<std::string, std::string> > attack_list = pkt_hnd.read_info_from_file(file_name);
    EXPECT_EQ(attack_list, pkt_hnd.read_info_from_file(file_name));
    attack_list.pop_back();
    EXPECT_NE(attack_list, pkt_hnd.read_info_from_file(file_name));
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
