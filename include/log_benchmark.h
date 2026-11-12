#ifndef LOG_BENCHMARK_H
#define LOG_BENCHAMRK_H


#include "get_governor_policy.h"
#include "operation.h"
#include <cjson/cJSON.h>
#include <openssl/crypto.h>

    
bool log_benchmark(double msec, size_t *len, operation op) {    

    
    if (op == ECDH_KEYGEN) {
        /** Opening a pointer to the benchmark file in mode append to register new rows 
         *  and writing some constants into the row
        */
        FILE *fpt;
        fpt = fopen("/home/diegor/projects/pqcbench/results/benchmark.csv", "a");

        /** Opening a pointer to cache file */
        FILE *jpt = fopen("/home/diegor/projects/pqcbench/results/cache.json", "r");
        if (!jpt) {
            printf("Error: could nor open cache.json file\n");
            return 1;
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
            return 1;
        }

        /** Access the JSON data */
        cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "ECDH-P256-KEYGEN-REPETITION");
        if (cJSON_IsNumber(name)) {
            printf("Name: %d\n", name->valueint);
        }

        /** Accesing to the system's governor policy for logging it into the benchmark */
        char governor[32];
        size_t govlngth = sizeof governor;
        if (!get_governor_policy(governor, govlngth)) return false;

        /** Accessing to system's version of Openssl for logging it into benchmark */
        const char* lib_version = OpenSSL_version(OPENSSL_VERSION_STRING);

        
        fprintf(fpt, "%s,%s,%s,%d,%.7f,%d,%s,%s,%s\n", "ECDH P-256", "default", 
                "keygen", name->valueint, msec, *(len), "OpenSSL", lib_version, governor);
        fclose(fpt);

        cJSON_SetNumberValue(name, name->valueint+1);
        char *json_str = cJSON_Print(json);

        jpt = fopen("/home/diegor/projects/pqcbench/results/cache.json", "w");

        printf("%s\n", json_str);
        fputs(json_str, jpt);
        fclose(jpt);

        cJSON_Delete(json);
        return true;


    } else if (op == ECDH_DERIVATION) {
        /** Opening a pointer to the benchmark file in mode append to register new rows 
        *  and writing some constants into the row
        */
        FILE *fpt;
        fpt = fopen("/home/diegor/projects/pqcbench/results/benchmark.csv", "a");

        /** Opening a pointer to cache file */
        FILE *jpt = fopen("/home/diegor/projects/pqcbench/results/cache.json", "r");
        if (!jpt) {
            printf("Error: could nor open cache.json file\n");
            return 1;
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
            return 1;
        }

        /** Access the JSON data */
        cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "ECDH-P256-DERIVATION-REPETITION");
        if (cJSON_IsNumber(name)) {
            printf("Name: %d\n", name->valueint);
        }

        /** Accesing to the system's governor policy for logging it into the benchmark */
        char governor[32];
        size_t govlngth = sizeof governor;
        if (!get_governor_policy(governor, govlngth)) return false;

        /** Accessing to system's version of Openssl for logging it into benchmark */
        const char* lib_version = OpenSSL_version(OPENSSL_VERSION_STRING);

        
        fprintf(fpt, "%s,%s,%s,%d,%.7f,%d,%s,%s,%s\n", "ECDH P-256", "default", 
                "derivation", name->valueint, msec, *(len), "OpenSSL", lib_version, governor);
        fclose(fpt);

        cJSON_SetNumberValue(name, name->valueint+1);
        char *json_str = cJSON_Print(json);

        jpt = fopen("/home/diegor/projects/pqcbench/results/cache.json", "w");

        printf("%s\n", json_str);
        fputs(json_str, jpt);
        fclose(jpt);

        cJSON_Delete(json);
        return true;
    }
   
   
}


#endif