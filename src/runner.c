#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cjson/cJSON.h>
#include <openssl/crypto.h>
#include <string.h>





int main(int argc, char *argv[]) {

    unsigned char *sub_process_name = "bin/ecdh";

    /** Reading the current system temperature */
    FILE *fpt = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (!fpt) {
        printf("Error: unable to open the temp file!\n");
        return 1;
    }

    int temp_c;
    fscanf(fpt, "%d", &temp_c);
    temp_c /= 1000;
    printf("temperature: %d° C\n", temp_c);
    fclose(fpt);


    /** Reading the current CPU frecuency in Khz */
    fpt = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (!fpt) {
        printf("Error: unable to open the freq file!\n");
        return 1;
    }
    int frec_khz;
    fscanf(fpt, "%d", &frec_khz);
    printf("Frecuencia: %d khz\n", frec_khz);
    fclose(fpt);


    /** Reading the system load average */
    fpt = fopen("/proc/loadavg", "r");
    if (!fpt) {
        printf("Error: unable to open the loadavg file!\n");
        return 1;
    }
    double loadavg;
    fscanf(fpt, "%lf", &loadavg);
    printf("loadavg: %lf\n", frec_khz);
    fclose(fpt);


    /** Reading the exit code of a subprocess (ecdh) */
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
    pid_t wait_result;

    while ((wait_result = wait(&status)) != -1) {
        printf("Process %lu returned result: %d\n", (unsigned long) wait_result, status);
    }

    printf("All children have finished.\n");


   

    return 0;
}