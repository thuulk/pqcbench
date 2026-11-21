#ifndef LOG_RUN_H
#define LOG_RUN_H

#include <stdbool.h>
#include <stdio.h>
#include <cjson/cJSON.h>
#include <openssl/crypto.h>
#include <string.h>


bool log_run(char *sub_process_name, long long ns, int status, int temp_c, int frec_khz, double loadavg) {
    /** Opening a pointer to the benchmark file in mode append to register new rows 
     *  and writing some constants into the row
    */
    FILE *fpt = fopen("results/runs.csv", "a");

    /** Opening a pointer to cache file */
    FILE *jpt = fopen("results/cache.json", "r");
    if (!jpt) {
        printf("Error: could nor open cache.json file\n");
        return false;
    }

    char jbuffer[1024];
    fread(jbuffer, 1, sizeof(jbuffer), jpt);
    fclose(jpt);

    /** Parse the JSON data */
    cJSON *json = cJSON_Parse(jbuffer);
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) printf("Error: %s", error_ptr);
        cJSON_Delete(json);
        return false;
    }

    /** Access the JSON data */
    cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "RUNNER-PROCESESS-REPETITION");

    
    fprintf(fpt, "%d,%s,%lld,%d,%d,%d,%f\n", name->valueint, sub_process_name, ns, status, temp_c, frec_khz, loadavg);
    fclose(fpt);

    unsigned int len = 9;
    if (strncmp(sub_process_name, "bin/mlkem", len) == 0) {
        cJSON_SetNumberValue(name, name->valueint+1);
    }
    char *json_str = cJSON_Print(json);

    jpt = fopen("results/cache.json", "w");
    fputs(json_str, jpt);
    fclose(jpt);

    cJSON_Delete(json);
    return true;
}


#endif