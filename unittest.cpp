#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include "dns_spoof.hpp"
#include <gtest/gtest.h>

bool compare(int a, int b);
int sum(int a, int b);

TEST(DISABLED_node_insert_test, linked_list_insert) { EXPECT_TRUE(compare(1, 1)); }
TEST(DISABLED_head_test, test_name) { EXPECT_EQ(3, sum(1,2)); }
TEST(capture_test, capture_test) { EXPECT_EQ(0, packet_capture_start()); }

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

bool compare(int a, int b){
    return a==b?true:false;
}

int sum(int a, int b){
    return a+b;
}