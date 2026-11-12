#include <stdio.h>


int main() {


    FILE *fpt;
    
    fpt = fopen("/home/diegor/projects/pqcbench/results/benchmark.csv", "w+");

    fprintf(fpt, "algorithm,config,operation,repetition,time_ns,output_size,library,version,governor_policy\n");


    return 0;
}