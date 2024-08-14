#include <iostream>
#include <unistd.h>
using namespace std;

int even_cnt = 0;
int odd_cnt = 0;
void even_work() {
    even_cnt++; 
}

void odd_work() {
    odd_cnt++;
}

int longLoop(uint64_t trip_count) {
    for(uint64_t i = 0; i < trip_count; i++) {
        if (i % 2) odd_work();
        else even_work();             
    } 
    
    cout<<even_cnt <<" " << odd_cnt<<endl;
    return 0;
}

int main() {
    for(int i = 0; i < 10; i++){
        cout<<longLoop(10000);
        sleep(1);
    }
    
    return 0;
}