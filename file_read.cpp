#include <cstdio>
#include <string>
#include <cstring>
#include <vector>
#include <utility>

std::vector<std::pair<std::string, std::string> > read_info_from_file(const char* file_name);
std::vector<std::string> make_domain_arr(std::vector<std::pair<std::string, std::string> > attack_list);
bool compare_domain(const char *target_domain, std::vector<std::string> domain_array);

int main(int argc, char* argv[]){
    if(argc!=2){
        printf("Error: Invalid args\n");
        return 0;
    }

    std::vector<std::pair<std::string, std::string> > attack_list;
    std::vector<std::string> domain_array;

    attack_list = read_info_from_file("info.txt");
    
    if(attack_list.size()!=0){
        domain_array = make_domain_arr(attack_list);

        if(compare_domain(argv[1], domain_array)){
            printf("Attack!\n");
        }else{
            printf("Fail... not matched info\n");
        }
    }else{
        printf("Error: Invalid file\n");
    }


    return 0;
}

std::vector<std::pair<std::string, std::string> > read_info_from_file(const char* file_name){
    std::vector<std::pair<std::string, std::string> > vec;

    FILE *fp;
    char line[256];
    fp = fopen(file_name, "r"); 

    if(fp==NULL){
        printf("Error: fail to open file\n");
        return vec;
    }

    while(!feof(fp)){
        std::pair<std::string, std::string> temp;

        char *ch = fgets(line, 80, fp);

        if(ch!=NULL){
            char *ip = strtok(line, " ");
            char *domain = strtok(NULL, "\n");

            std::string str_ip(ip);
            std::string str_domain(domain);

            temp = std::make_pair(str_ip, str_domain);

            vec.push_back(temp);
        }
    }

    fclose(fp);

    return vec;
}

std::vector<std::string> make_domain_arr(std::vector<std::pair<std::string, std::string> > attack_list){
    std::vector<std::string> temp;
    
    for(int i=0;i<attack_list.size();i++){
        temp.push_back(attack_list[i].second);
    }

    return temp;
}

bool compare_domain(const char *target_domain, std::vector<std::string> domain_array){
    for(int i=0;i<domain_array.size();i++){
        if(strcmp(target_domain, domain_array[i].c_str())==0){
            return true;
        }
    }

    return false;
}