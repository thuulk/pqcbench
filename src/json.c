#include <stdio.h>
#include <cjson/cJSON.h>


int main() {


    /** Create the json object */
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "ECDH-P256-KEYGEN-REPETITION", 0);
    cJSON_AddNumberToObject(json, "ECDH-P256-DERIVATION-REPETITION", 0);
    cJSON_AddNumberToObject(json, "MLKEN-768-KEYGEN-REPETITION", 0);
    cJSON_AddNumberToObject(json, "MLKEN-768-ENCAPS-REPETITION", 0);
    cJSON_AddNumberToObject(json, "MLKEN-768-DECAPS-REPETITION", 0);

    /** Convert the cJSON object to a JSON string */
    char *json_str = cJSON_Print(json);

    /** Write the JSON string to a file */
    FILE *fpt = fopen("/home/diegor/projects/pqcbench/results/cache.json", "w");
    if (!fpt) {
        printf("Error: unable to open the file.\n");
        return 1;
    }

    printf("%s\n", json_str);
    fputs(json_str, fpt);
    fclose;
    
    /** free the JSON string and cJSON object */
    cJSON_free(json_str);
    cJSON_Delete(json);   
    
    return 0;
}