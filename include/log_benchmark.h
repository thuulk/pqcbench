#ifndef LOG_BENCHMARK_H
#define LOG_BENCHAMRK_H


#include "get_governor_policy.h"
#include "operation.h"
#include <cjson/cJSON.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdbool.h>
    
bool log_benchmark(long long t, size_t *len, unsigned char* json_ob, 
                    unsigned char* algorithm_name, unsigned char* op) {    

    
    /** Opening a pointer to the benchmark file in mode append to register new rows 
     *  and writing some constants into the row
    */
    FILE *fpt;
    fpt = fopen("results/benchmark.csv", "a");

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
    cJSON *name = cJSON_GetObjectItemCaseSensitive(json, json_ob);
    if (cJSON_IsNumber(name)) {
        printf("Name: %d\n", name->valueint);
    }

    /** Accesing to the system's governor policy for logging it into the benchmark */
    char governor[32];
    size_t govlngth = sizeof governor;
    if (!get_governor_policy(governor, govlngth)) return false;

    /** Accessing to system's version of Openssl for logging it into benchmark */
    const char* lib_version = OpenSSL_version(OPENSSL_VERSION_STRING);

    
    fprintf(fpt, "%s,%s,%s,%d,%lld,%d,%s,%s,%s\n", algorithm_name, "default", 
            op, name->valueint, t, *(len), "OpenSSL", lib_version, governor);
    fclose(fpt);

    cJSON_SetNumberValue(name, name->valueint+1);
    char *json_str = cJSON_Print(json);

    jpt = fopen("results/cache.json", "w");

    fputs(json_str, jpt);
    fclose(jpt);

    cJSON_Delete(json);
    return true;
   
   
}


#endif
