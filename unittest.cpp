
#include <gtest/gtest.h>
#include "packet_handler.hpp"

TEST(attack_test, capture_test) {
    packet_handle pkt_hnd = packet_handle();
    char file_name[128] = "info";

    EXPECT_NO_THROW(pkt_hnd.set_attack_info_file(file_name));
    EXPECT_NO_THROW(pkt_hnd.read_info_from_file());
    EXPECT_NO_THROW(pkt_hnd.set_dom_and_ip());
    EXPECT_EQ(0, pkt_hnd.packet_capture_start());
    EXPECT_NO_THROW(pkt_hnd.set_my_ip());
    EXPECT_NO_THROW(pkt_hnd.print_capture_info());
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