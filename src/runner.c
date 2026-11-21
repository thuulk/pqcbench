#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../include/sub_timespec.h"
#include "../include/log_run.h"



int run(char* sub_process_name) {
    struct timespec start, finish;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /** Reading the exit code of a subprocess */
    char *argv[] = { sub_process_name, NULL };
    pid_t process;
    process = fork();

    if (process < 0)
    {
        // fork() failed.
        perror("fork");
        return 2;
    }

    if (process == 0)
    {
        // sub-process
        argv[0] = sub_process_name; // Just need to change where argv[0] points to.
        execv(argv[0], argv);
        perror("execv"); // Ne need to check execv() return value. If it returns, you know it failed.
        return 2;
    }

    int status;
    wait(&status);

    /** Reading the current system temperature */
    FILE *fpt = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (!fpt) {
        printf("Error: unable to open the temp file!\n");
        return 1;
    }

    int temp_c;
    fscanf(fpt, "%d", &temp_c);
    temp_c /= 1000;
    fclose(fpt);


    /** Reading the current CPU frecuency in Khz */
    fpt = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (!fpt) {
        printf("Error: unable to open the freq file!\n");
        return 1;
    }
    int frec_khz;
    fscanf(fpt, "%d", &frec_khz);
    fclose(fpt);


    /** Reading the system load average */
    fpt = fopen("/proc/loadavg", "r");
    if (!fpt) {
        printf("Error: unable to open the loadavg file!\n");
        return 1;
    }
    double loadavg;
    fscanf(fpt, "%lf", &loadavg);
    fclose(fpt);

    clock_gettime(CLOCK_MONOTONIC, &finish);
    long long ns = elapsed_ns(start, finish);
    log_run(sub_process_name, ns, status, temp_c, frec_khz, loadavg);
}



int main(void) {
    
    for (__uint16_t i = 0; i < 1000; i++) {
        run("bin/ecdh");
        run("bin/mlkem");
    }

    return 0;
}