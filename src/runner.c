#include <stdio.h>



int main(void) {

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


    fpt = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (!fpt) {
        printf("Error: unable to open the freq file!\n");
        return 1;
    }
    int frec_hz;
    fscanf(fpt, "%d", &frec_hz);
    double frec_ghz = frec_hz/1e6;
    printf("Frecuencia: %.1f gHz\n", frec_ghz);
    fclose(fpt);

    return 0;
}