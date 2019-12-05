#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <gtest/gtest.h>

#include "packet_handler.cpp"

TEST(attack_test, capture_test) {
    packet_handle *pkt_hnd = (packet_handle*)malloc(sizeof(packet_handle));
    
    char file_name[128] = "info";
    pkt_hnd->set_attack_info_file(file_name);

    EXPECT_EQ(0, pkt_hnd->packet_capture_start()); 

    delete pkt_hnd;
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