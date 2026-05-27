#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

#define MAX_RETRIES 3

// ------------------------------------------------------------
//  Curl write callback
// ------------------------------------------------------------
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// ------------------------------------------------------------
//  Read API key from file (first line)
// ------------------------------------------------------------
char* read_api_key_from_file(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (!file) return NULL;
    char *key = malloc(1024);
    if (!key) { fclose(file); return NULL; }
    if (fgets(key, 1024, file) == NULL) { free(key); fclose(file); return NULL; }
    key[strcspn(key, "\r\n")] = 0;
    fclose(file);
    return key;
}

// ------------------------------------------------------------
//  Remove any line containing "#include" from the C code
// ------------------------------------------------------------
char* remove_includes(const char* src) {
    if (!src) return NULL;
    size_t len = strlen(src);
    char *dst = malloc(len + 1);
    if (!dst) return NULL;
    const char *p = src;
    char *q = dst;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "#include", 8) == 0) {
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
            continue;
        }
        while (*p && *p != '\n') *q++ = *p++;
        if (*p == '\n') *q++ = *p++;
    }
    *q = '\0';
    return dst;
}

// ------------------------------------------------------------
//  Send a prompt to Gemini and return the raw text response
// ------------------------------------------------------------
char* ask_gemini(const char* api_key, const char* prompt) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk = { malloc(1), 0 };
    if (!chunk.memory) return NULL;

    char url[] = "https://generativelanguage.googleapis.com/v1/models/gemini-3.5-flash:generateContent";

    char json_payload[8192];
    // Escape double quotes and backslashes in prompt for JSON
    char *escaped_prompt = malloc(strlen(prompt) * 2 + 1);
    if (!escaped_prompt) { free(chunk.memory); return NULL; }
    const char *src = prompt;
    char *dst = escaped_prompt;
    while (*src) {
        if (*src == '"' || *src == '\\') *dst++ = '\\';
        *dst++ = *src++;
    }
    *dst = '\0';

    snprintf(json_payload, sizeof(json_payload),
        "{\"contents\": [{\"parts\": [{\"text\": \"%s\"}]}]}", escaped_prompt);
    free(escaped_prompt);

    curl = curl_easy_init();
    if (!curl) {
        free(chunk.memory);
        return NULL;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    char key_header[256];
    snprintf(key_header, sizeof(key_header), "x-goog-api-key: %s", api_key);
    headers = curl_slist_append(headers, key_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(chunk.memory);
        fprintf(stderr, "CURL error: %s\n", curl_easy_strerror(res));
        return NULL;
    }

    cJSON *json = cJSON_Parse(chunk.memory);
    free(chunk.memory);
    if (!json) return NULL;

    cJSON *candidates = cJSON_GetObjectItem(json, "candidates");
    if (!cJSON_IsArray(candidates) || cJSON_GetArraySize(candidates) == 0) {
        cJSON_Delete(json);
        return NULL;
    }
    cJSON *first = cJSON_GetArrayItem(candidates, 0);
    cJSON *content = cJSON_GetObjectItem(first, "content");
    cJSON *parts = cJSON_GetObjectItem(content, "parts");
    if (!cJSON_IsArray(parts) || cJSON_GetArraySize(parts) == 0) {
        cJSON_Delete(json);
        return NULL;
    }
    cJSON *first_part = cJSON_GetArrayItem(parts, 0);
    cJSON *text = cJSON_GetObjectItem(first_part, "text");
    if (!cJSON_IsString(text)) {
        cJSON_Delete(json);
        return NULL;
    }

    char *result = strdup(text->valuestring);
    cJSON_Delete(json);
    return result;
}

// ------------------------------------------------------------
//  Try to compile C code into shellcode.
//  Returns 0 on success, -1 on failure, and writes error to "compile_error.log"
// ------------------------------------------------------------
int try_compile(const char* clean_code, const char* array_name, const char* user_task) {
    // Write temporary C file
    FILE *temp_c = fopen("temp_shellcode.c", "w");
    if (!temp_c) return -1;
    fprintf(temp_c, "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n");
    fprintf(temp_c, "void shellcode_function() {\n    %s\n}\n\n", clean_code);
    fprintf(temp_c, "int main() { shellcode_function(); return 0; }\n");
    fclose(temp_c);

    // Compile, capturing errors to a file
    int ret = system("gcc -c -fPIC -O2 -o temp_shellcode.o temp_shellcode.c 2>compile_error.log");
    if (ret != 0) {
        return -1;  // compilation failed
    }

    // Extract .text section
    if (system("objcopy -j .text -O binary temp_shellcode.o temp_shellcode.bin 2>/dev/null") != 0) {
        return -1;
    }

    // Read binary shellcode
    FILE *bin = fopen("temp_shellcode.bin", "rb");
    if (!bin) return -1;
    fseek(bin, 0, SEEK_END);
    long size = ftell(bin);
    fseek(bin, 0, SEEK_SET);
    if (size <= 0) { fclose(bin); return -1; }
    unsigned char *shellcode = malloc(size);
    if (!shellcode) { fclose(bin); return -1; }
    fread(shellcode, 1, size, bin);
    fclose(bin);

    // Print info
    printf("Shellcode size: %ld bytes\n", size);
    printf("Hex dump:\n");
    for (long i = 0; i < size; i++) {
        if (i % 16 == 0) printf("\n%04lx: ", i);
        printf("%02x ", shellcode[i]);
    }
    printf("\n\n");

    // Append to header file (same logic as before)
    FILE *header = fopen("shellcode.h", "r");
    char *content = NULL;
    long file_size = 0;
    int macro_exists = 0;
    if (header) {
        fseek(header, 0, SEEK_END);
        file_size = ftell(header);
        rewind(header);
        content = malloc(file_size + 1);
        if (!content) { fclose(header); free(shellcode); return -1; }
        fread(content, 1, file_size, header);
        content[file_size] = '\0';
        fclose(header);
        if (strstr(content, "#define call_shellcode(")) macro_exists = 1;
    }

    FILE *out = fopen("shellcode.h", "w");
    if (!out) { free(shellcode); free(content); return -1; }

    if (!content) {
        fprintf(out, "#ifndef SHELLCODE_H\n#define SHELLCODE_H\n\n#include <stdio.h>\n\n");
        fprintf(out, "#define call_shellcode(shellcode, ...) \\\n");
        fprintf(out, "    ((int (*)(__VA_ARGS__))shellcode)(__VA_ARGS__)\n\n");
        fprintf(out, "/* --- Task: %s --- */\n", user_task);
        fprintf(out, "static unsigned char %s[] = {\n    ", array_name);
        for (long i = 0; i < size; i++) {
            fprintf(out, "0x%02x", shellcode[i]);
            if (i < size-1) fprintf(out, ", ");
            if ((i+1) % 12 == 0 && i != size-1) fprintf(out, "\n    ");
        }
        fprintf(out, "\n};\n\n#endif /* SHELLCODE_H */\n");
    } else {
        char *endif_pos = strstr(content, "#endif /* SHELLCODE_H */");
        if (!endif_pos) {
            fprintf(out, "%s", content);
            fprintf(out, "\n/* --- Task: %s --- */\n", user_task);
            fprintf(out, "static unsigned char %s[] = {\n    ", array_name);
            for (long i = 0; i < size; i++) {
                fprintf(out, "0x%02x", shellcode[i]);
                if (i < size-1) fprintf(out, ", ");
                if ((i+1) % 12 == 0 && i != size-1) fprintf(out, "\n    ");
            }
            fprintf(out, "\n};\n\n#endif /* SHELLCODE_H */\n");
        } else {
            long pos = endif_pos - content;
            fwrite(content, 1, pos, out);
            if (!macro_exists) {
                fprintf(out, "\n#define call_shellcode(shellcode, ...) \\\n");
                fprintf(out, "    ((int (*)(__VA_ARGS__))shellcode)(__VA_ARGS__)\n\n");
            }
            fprintf(out, "\n/* --- Task: %s --- */\n", user_task);
            fprintf(out, "static unsigned char %s[] = {\n    ", array_name);
            for (long i = 0; i < size; i++) {
                fprintf(out, "0x%02x", shellcode[i]);
                if (i < size-1) fprintf(out, ", ");
                if ((i+1) % 12 == 0 && i != size-1) fprintf(out, "\n    ");
            }
            fprintf(out, "\n};\n\n");
            fwrite(endif_pos, 1, file_size - pos, out);
        }
        free(content);
    }

    fclose(out);
    free(shellcode);
    system("rm -f temp_shellcode.c temp_shellcode.o temp_shellcode.bin");
    return 0;
}

// ------------------------------------------------------------
//  Main: loop with Gemini retries on compilation failure
// ------------------------------------------------------------
int main(void) {
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║     AI Shellcode Generator (Gemini API)         ║\n");
    printf("║     Automatic error correction                   ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    char *api_key = read_api_key_from_file("GEMINI_API_KEY");
    if (!api_key) {
        fprintf(stderr, "\n❌ ERROR: Could not read API key from GEMINI_API_KEY\n");
        fprintf(stderr, "Create the file with: echo 'YOUR_API_KEY' > GEMINI_API_KEY\n");
        return 1;
    }

    char array_name[256];
    printf("\n📝 Enter a name for this shellcode array (e.g., my_add_func): ");
    if (fgets(array_name, sizeof(array_name), stdin) == NULL) {
        free(api_key);
        return 1;
    }
    array_name[strcspn(array_name, "\n")] = 0;
    if (strlen(array_name) == 0) {
        strcpy(array_name, "default_shellcode");
        printf("   Using default name: %s\n", array_name);
    }

    char user_task[2048];
    printf("\n🔧 Enter the function description (e.g., '2+2', 'print Hello World'):\n");
    if (fgets(user_task, sizeof(user_task), stdin) == NULL) {
        free(api_key);
        return 1;
    }
    user_task[strcspn(user_task, "\n")] = 0;
    if (strlen(user_task) == 0) {
        strcpy(user_task, "a function that prints 'Hello from shellcode!'");
        printf("   Using default task: %s\n", user_task);
    }

    char prompt[4096];
    snprintf(prompt, sizeof(prompt),
             "Generate ONLY C code (no explanations, no markdown, no backticks). "
             "Generate a C function that %s. "
             "The code should be a complete function body. "
             "Use only standard C libraries. Do NOT include any #include directives. "
             "If arguments are needed, assume they are passed as parameters. "
             "Return the function body only.",
             user_task);

    char *generated_c = NULL;
    int success = 0;

    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        printf("\n🤖 Contacting Gemini (attempt %d/%d)...\n", attempt, MAX_RETRIES);
        if (generated_c) {
            free(generated_c);
            generated_c = NULL;
        }
        generated_c = ask_gemini(api_key, prompt);
        if (!generated_c) {
            fprintf(stderr, "❌ Failed to get response from Gemini.\n");
            continue;
        }

        printf("\n📄 Generated C code (function body):\n");
        printf("─────────────────────────────────────────────────\n");
        printf("%s\n", generated_c);
        printf("─────────────────────────────────────────────────\n");

        // Remove any stray #include lines
        char *clean_code = remove_includes(generated_c);
        if (!clean_code) {
            fprintf(stderr, "Failed to sanitize code.\n");
            continue;
        }

        printf("\n🔧 Compiling to shellcode...\n");
        int comp_ok = try_compile(clean_code, array_name, user_task);
        free(clean_code);

        if (comp_ok == 0) {
            success = 1;
            break;
        }

        // Compilation failed – read error log
        FILE *err = fopen("compile_error.log", "r");
        char error_msg[4096] = {0};
        if (err) {
            fread(error_msg, 1, sizeof(error_msg)-1, err);
            fclose(err);
        } else {
            strcpy(error_msg, "Unknown compilation error.");
        }

        printf("\n⚠️  Compilation failed. Error:\n%s\n", error_msg);
        printf("🔄 Asking Gemini to fix the code...\n");

        // Prepare a new prompt with the original code and the error
        snprintf(prompt, sizeof(prompt),
                 "The following C function body failed to compile.\n"
                 "Original code:\n```\n%s\n```\n"
                 "Compiler error:\n```\n%s\n```\n"
                 "Please provide a corrected version. Return ONLY the corrected function body, "
                 "no explanations, no markdown, no backticks, and no #include directives.",
                 generated_c, error_msg);
    }

    free(api_key);

    if (success) {
        printf("\n✅ Success! Shellcode appended to shellcode.h\n");
        printf("\n📌 How to use in main.c (variadic macro):\n");
        printf("─────────────────────────────────────────────────\n");
        printf("#include \"shellcode.h\"\n\n");
        printf("int main() {\n");
        printf("    int result = call_shellcode(%s, 2, 3);\n", array_name);
        printf("    printf(\"Result: %%d\\n\", result);\n");
        printf("    // call_shellcode(%s); // for no arguments\n", array_name);
        printf("    return 0;\n");
        printf("}\n");
        printf("─────────────────────────────────────────────────\n");
        printf("\n🚀 Compile with: gcc -o program main.c -z execstack\n");
        printf("   Then run: ./program\n");
    } else {
        fprintf(stderr, "\n❌ Failed to produce compilable shellcode after %d attempts.\n", MAX_RETRIES);
    }

    if (generated_c) free(generated_c);
    return success ? 0 : 1;
}
