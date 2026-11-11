#ifndef GET_GOVERNOR_POLICY_H
#define GET_GOVERNOR_POLICY_H

#include <stdio.h>
#include <string.h>

bool get_governor_policy(char *buffer, size_t size) {

    FILE *gpt = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
    if (!gpt || !fgets(buffer, size, gpt)) {
        printf("Error retrieving the system governor's policy\n");
        return false;
    }
    fclose(gpt);
    buffer[strcspn(buffer, "\n")] = '\0';
    return true;

}


#endif
