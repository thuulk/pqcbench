#include <stdio.h>


int main() {


    /** Benchmark of criptographic operations */
    FILE *fpt;
    
    fpt = fopen("results/benchmark.csv", "w+");

    fprintf(fpt, "algorithm,config,operation,repetition,time_ns,output_size,library,version,governor_policy\n");
    fclose(fpt);

    /** Benchmark of system conditions */
    fpt = fopen("results/runs.csv", "w");
    fprintf(fpt, "run,binary,time_ns,exit_code,temp_c,frec_khz,load_avg");

    return 0;
}
