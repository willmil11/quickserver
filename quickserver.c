#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "libs/cJSON.h"
#include "libs/cJSON.c"

#undef can_read

#define MG_ENABLE_LOG 0  // disable Mongoose internal logging noise
#define MG_TLS MG_TLS_OPENSSL
#define MG_ENABLE_IPV6 1
#include "libs/mongoose.h"
#include "libs/mongoose.c"

#include "libs/fs_utils.c"

static bool g_https_enabled = false;
static char* g_tls_cert_data = NULL;
static char* g_tls_key_data = NULL;

typedef struct {
    char ip[40];
    bool ip_type; //true is ipv4 false is ipv6
    char method[8];
    char* body; //if any else NULL
    char* headers;
} reqData;

typedef struct {
    char* resp_data;
    int http_code;
    char* resp_headers;
} reqResp;

reqResp handle_request(reqData req){
    printf("Received request, data:\n");
    printf("ip: %s\n", req.ip);
    printf("ip_type: %s\n", req.ip_type ? "ipv4" : "ipv6");
    printf("method: %s\n", req.method);
    if (req.body){
        printf("body: %s\n", req.body);
    }
    else{
        printf("body: no body\n");
    }
    if (req.headers){
        printf("headers: %s\n", req.headers);
    }
    else{
        printf("headers: no headers\n");
    }

    printf("Constructing resp and sending\n");
    reqResp resp;
    resp.http_code = 200;
    resp.resp_data = NULL;
    resp.resp_headers = NULL;
    char* resp_data = malloc(strlen("Hello, world!") + 1);
    if (!resp_data){
        printf("Failed to allocate memory for test.\n");
        exit(1);
    }
    strcpy(resp_data, "Hello, world!");
    resp.resp_data = resp_data;

    const char* header_value = "Content-Type: text/plain\r\n";
    char* resp_headers = malloc(strlen(header_value) + 1);
    if (!resp_headers){
        printf("Failed to allocate memory for response headers.\n");
        free(resp_data);
        exit(1);
    }
    strcpy(resp_headers, header_value);
    resp.resp_headers = resp_headers;

    return resp;
}

static void addr_to_str(const struct mg_addr *addr, char *buf, size_t len) {
    if (!buf || len == 0) {
        return;
    }
    if (addr->is_ip6) {
        struct in6_addr in6;
        memcpy(&in6, addr->ip, sizeof(in6));
        inet_ntop(AF_INET6, &in6, buf, len);
    } else {
        struct in_addr in4;
        memcpy(&in4, addr->ip, sizeof(in4));
        inet_ntop(AF_INET, &in4, buf, len);
    }
}

void qs_http_cb(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_ACCEPT){
        if (g_https_enabled){
            struct mg_tls_opts opts = {
                .cert = mg_str(g_tls_cert_data),
                .key = mg_str(g_tls_key_data),
            };
            mg_tls_init(c, &opts);
        }
        return;
    }
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        // Build reqData
        reqData rd = {0};

        // Remote IP + type
        addr_to_str(&c->rem, rd.ip, sizeof(rd.ip));       // fills IPv4 or IPv6 text
        rd.ip_type = !c->rem.is_ip6;                  // true if IPv4, false if IPv6

        // Method (fit into 7 chars + NUL)
        size_t mlen = hm->method.len < (sizeof(rd.method) - 1) ? hm->method.len : (sizeof(rd.method) - 1);
        memcpy(rd.method, hm->method.buf, mlen);
        rd.method[mlen] = '\0';

        // Body (malloc + NUL)
        if (hm->body.len > 0) {
            rd.body = (char*) malloc(hm->body.len + 1);
            if (rd.body == NULL) {
                mg_http_reply(c, 500, "", "Internal Server Error");
                return;
            }
            memcpy(rd.body, hm->body.buf, hm->body.len);
            rd.body[hm->body.len] = '\0';
        } else {
            rd.body = NULL;
        }

        // Headers -> single string "Name: Value\r\n..."
        size_t total_hlen = 0;
        for (int i = 0; i < MG_MAX_HTTP_HEADERS && hm->headers[i].name.len > 0; i++) {
            total_hlen += hm->headers[i].name.len + 2 /*": "*/ + hm->headers[i].value.len + 2 /*"\r\n"*/;
        }
        rd.headers = (char*) malloc(total_hlen + 1);
        if (rd.headers == NULL) {
            if (rd.body) free(rd.body);
            mg_http_reply(c, 500, "", "Internal Server Error");
            return;
        }
        char *hp = rd.headers;
        for (int i = 0; i < MG_MAX_HTTP_HEADERS && hm->headers[i].name.len > 0; i++) {
            memcpy(hp, hm->headers[i].name.buf, hm->headers[i].name.len);
            hp += hm->headers[i].name.len;
            memcpy(hp, ": ", 2);
            hp += 2;
            memcpy(hp, hm->headers[i].value.buf, hm->headers[i].value.len);
            hp += hm->headers[i].value.len;
            memcpy(hp, "\r\n", 2);
            hp += 2;
        }
        *hp = '\0';

        // Call your handler
        reqResp rr = handle_request(rd);

        // Defaults if not set
        const char *resp_headers = rr.resp_headers ? rr.resp_headers : "";
        const char *resp_body    = rr.resp_data    ? rr.resp_data    : "";
        int code = rr.http_code ? rr.http_code : 200;

        // Send response
        mg_http_reply(c, code, resp_headers, "%s", resp_body);

        // Cleanup
        if (rd.body) free(rd.body);
        if (rd.headers) free(rd.headers);
    }
}

int main(int argc, char** argv){
    if (argc == 2){
        if (strcmp(argv[1], "help") == 0){
            printf("[Quickserver] [Help] Hello, this is a simple guide on how to use this software:\n");
            printf("[Quickserver] [Help] This is a webserver software that handles both http and https, this means that you can use it to make a webserver that serves files in a simple non encrypted way as well as a secure, encrypted way. The first requires just the first three arguments while the latter requires all the fifth arguments.\n");
            printf("[Quickserver] [Help] To use this software, you have to execute it with a few arguments:\n");
            printf("[Quickserver] [Help]     - The first argument is the path to the content you wish to serve to the user that connects to this webserver, it must be a valid path to a folder, inside it 'index.html' is the default file that will be served to the user if they don't specify a path (e.g. example.com), although if 'index.html' does not exist, a default page built into the software will be served. And if they do specify a path, and if that path is a file (e.g. example.com/coolpicture.png) it will be served simply, although if it is a directory (example.com/mywebsite), the webserver will search for 'index.html' in that directory and if it does not exist will provide the list of files in the directory as plain text. The webserver will always try to set the correct 'Content-Type' response header on the response based on the file's extension. If the path requested by the client does not exist in the path specified in the first argument, the webserver will search for '404.html' in the path specified in the first argument and serve it, if it does not exist a default page built into this software will be served instead.\n");
            printf("[Quickserver] [Help]     - The second argument is the path to the log directory, it is a directory where the webserver will write logs for every request named following the format 'month-day-year_hour:minute:second:millisecond.json'. The logs contain the client's ip, their request's headers, body, url and method formatted as a json object for easier automatic parsing, if it is not easy on the eyes which I can totally understand, simply run 'quickserver analyse-log /path/to/log' to get a more readable view.\n");
            printf("[Quickserver] [Help]     - The third argument is the port to serve the content on, it is a number between 1 and 65535 that you have to choose, you cannot run two (or more) softwares on a single port and some ports are privileged, the default ports browsers use for http and https are 80 and 443 respectively, please note that at least on linux those are privileged ports, you will therefore need to run the software as superuser, but for testing or other use cases that only require high ports such as 8080 you can just run the software with your users without any issues (if the port is not already used).\n");
            printf("[Quickserver] [Help]     - The fourth argument is the path to the pem file, providing it along with the fifth argument (the key file) that I am gonna talk about right after this one will turn on the https mode of the server. Those files are required to use https on a webserver. They are given by your certificate provider, there are some free ones like let's encrypt which you can use.\n");
            printf("[Quickserver] [Help]     - The fifth argument is the path to the key file, providing it along with the fourth argument (the pem file) that I just talked about right before this one will turn on the https mode of the server. Those files are required to use https on a webserver. They are given by your certificate eprovider, there are some free ones like let's encrypt which you can use.\n");
            printf("[Quickserver] [Help] Example of usage:\n");
            printf("[Quickserver] [Help] Say you have this file structure:\n");
            printf("[Quickserver] [Help] server\n");
            printf("[Quickserver] [Help]   -> index.html\n");
            printf("[Quickserver] [Help]   -> news\n");
            printf("[Quickserver] [Help]        -> index.html\n");
            printf("[Quickserver] [Help]        -> fish.png\n");
            printf("[Quickserver] [Help] logs\n");
            printf("[Quickserver] [Help] server.pem\n");
            printf("[Quickserver] [Help] server.key\n");
            printf("[Quickserver] [Help] Here you could start a webserver using the command:\n");
            printf("[Quickserver] [Help] quickserver server/ logs/ 443 server.pem server.key\n");
            printf("[Quickserver] [Help] This would start an https webserver on port 443 (if you have sufficient privileges, serving the content in server and storing the logs in logs. Say the server is accessible at 'example.com', accessing 'example.com' would serve file 'index.html', accessing 'example.com/news' would serve file 'index.html' in 'news', accessing 'example.com/news/fish.png' would serve file 'fish.png' in news and accessing 'example.com/cat' would serve the default '404.html' embedded in this software as no '404.html' is present in the directory to serve.\n");
            printf("[Quickserver] [Help] If you need additional help that isn't here, you can contact me by email: willmil111012@gmail.com, or preferably by discord (willmil11).\n");
            return 0;
        }
        else{
            printf("[Quickserver] Invalid number of args.\n");
            printf("[Quickserver] Correct usage (args between square brackets are for https only):\n");
            printf("[Quickserver] quickserver /path/to/serve /path/to/logs port [/path/to/pem /path/to/key]\n");
            printf("[Quickserver] or\n");
            printf("[Quickserver] quickserver help\n");
            printf("[Quickserver] or\n");
            printf("[Quickserver] quickserver analyse-log /path/to/log.json\n");
            printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
            return 1;
        }
    }
    if (argc == 3){
        if (strcmp(argv[1], "analyse-log") == 0){
            if (!is_file(argv[2])){
                printf("[Quickserver] Log path provided does not exist/is not a file.\n");
                return 1;
            }

            printf("[Quickserver] Reading log file...\n");
            char* content = file_read(argv[2]);
            if (!content){
                printf("[Quickserver] Failed to read log file. Common reasons include: insufficient privileges...\n");
                return 1;
            }
            printf("[Quickserver] Log file read.\n");
            printf("[Quickserver] Parsing log...\n");
            cJSON* log = cJSON_Parse(content);
            if (!log){
                printf("[Quickserver] Failed to parse log, invalid json.\n");
                return 1;
            }
            printf("[Quickserver] Parsed log.\n");
            free(content);

            void corrupt_log(){
                printf("[Quickserver] Log file is corrupted.\n");
                exit(1);
            }

            if (!cJSON_IsObject(log)){
                corrupt_log();
            }
            cJSON* client_ip = cJSON_GetObjectItem(log, "client_ip");
            cJSON* request_url = cJSON_GetObjectItem(log, "request_url");
            cJSON* request_headers = cJSON_GetObjectItem(log, "request_headers");
            cJSON* request_body = cJSON_GetObjectItem(log, "request_body");
            cJSON* request_method = cJSON_GetObjectItem(log, "request_method");
            if ((client_ip == NULL) || (request_url == NULL) || (request_headers == NULL) || (request_body == NULL) || (request_method == NULL)){
                corrupt_log();
            }

            if ((!cJSON_IsString(client_ip)) || (!cJSON_IsString(request_url)) || (!cJSON_IsString(request_headers)) || (!cJSON_IsString(request_body)) || (!cJSON_IsString(request_method))){
                corrupt_log();
            }

            char* client_ip_dat = strdup(client_ip->valuestring);
            char* request_url_dat = strdup(request_url->valuestring);
            char* request_headers_dat = strdup(request_headers->valuestring);
            char* request_body_dat = strdup(request_body->valuestring);
            char* request_method_dat = strdup(request_method->valuestring);

            if ((!client_ip_dat) || (!request_url_dat) || (!request_headers_dat) || (!request_body_dat) || (!request_method_dat)){
                printf("[Quickserver] Failed to allocate memory to analyse log.\n");
                return 1;
            }

            cJSON_Delete(log);

            //Decypher the name of the log.
            char* name = argv[2];
            while (strstr(name, "/") || strstr(name, "\\")){
                name += 1;
            }

            char** splits = NULL;
            int splits_len = 0;

            char* accumulate = NULL;
            int accumulate_len = 0;

            int name_len = strlen(name);

            int end = 0;

            for (int index = 0; index < name_len; index++){
                if (name[index] == '-'){
                    splits_len++;
                    splits = realloc(splits, splits_len * sizeof(char*));
                    if (!splits){
                        printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                        return 1;
                    }
                    accumulate = realloc(accumulate, accumulate_len + 1);
                    if (!accumulate){
                        printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                        return 1;
                    }
                    accumulate[accumulate_len] = '\0';
                    splits[splits_len - 1] = accumulate;
                    accumulate_len = 0;
                    accumulate = NULL;
                }
                else{
                    if (name[index] == '_'){
                        end = index;
                        break;
                    }
                    accumulate_len++;
                    accumulate = realloc(accumulate, accumulate_len);
                    if (!accumulate){
                        printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                        return 1;
                    }
                    accumulate[accumulate_len - 1] = name[index];
                }
                end = index;
            }

            if (accumulate_len > 0) {
                accumulate = realloc(accumulate, accumulate_len + 1);
                if (!accumulate) {
                    printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                    return 1;
                }
                accumulate[accumulate_len] = '\0';
                splits_len++;
                splits = realloc(splits, splits_len * sizeof(char *));
                if (!splits) {
                    printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                    return 1;
                }
                splits[splits_len - 1] = accumulate;
                accumulate = NULL;
                accumulate_len = 0;
            }

            if (splits_len != 3){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }

            char* month = splits[0];
            char* day = splits[1];
            char* year = splits[2];
            
            free(splits);

            splits = NULL;
            accumulate = NULL;
            splits_len = 0;
            accumulate_len = 0;
            
            name += end + 1; //we are now after _;
            name_len = strlen(name);

            for (int index = 0; index < name_len; index++){
                if (name[index] == ':'){
                    splits_len++;
                    splits = realloc(splits, splits_len * sizeof(char*));
                    if (!splits){
                        printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                        return 1;
                    }
                    accumulate = realloc(accumulate, accumulate_len + 1);
                    if (!accumulate){
                        printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                        return 1;
                    }
                    accumulate[accumulate_len] = '\0';
                    splits[splits_len - 1] = accumulate;
                    accumulate_len = 0;
                    accumulate = NULL;
                }
                else{
                    if (name[index] == '.'){
                        end = index;
                        break;
                    }
                    accumulate_len++;
                    accumulate = realloc(accumulate, accumulate_len);
                    if (!accumulate){
                        printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                        return 1;
                    }
                    accumulate[accumulate_len - 1] = name[index];
                }
                end = index;
            }

            if (accumulate_len > 0) {
                accumulate = realloc(accumulate, accumulate_len + 1);
                if (!accumulate) {
                    printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                    return 1;
                }
                accumulate[accumulate_len] = '\0';
                splits_len++;
                splits = realloc(splits, splits_len * sizeof(char *));
                if (!splits) {
                    printf("[Quickserver] Failed to allocate memory to parse log name.\n");
                    return 1;
                }
                splits[splits_len - 1] = accumulate;
                accumulate = NULL;
                accumulate_len = 0;
            }

            if (splits_len != 4){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }

            char* hour = splits[0];
            char* minute = splits[1];
            char* second = splits[2];
            char* millisecond = splits[3];

            free(splits);

            if ((strlen(month) != 2) || (strlen(day) != 2) || (strlen(hour) != 2) || (strlen(minute) != 2) || (strlen(second) != 2) || (strlen(millisecond) != 3)){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }

            int month_dat = atoi(month);
            int day_dat = atoi(day);
            int year_dat = atoi(year);
            int hour_dat = atoi(hour);
            int minute_dat = atoi(minute);
            int second_dat = atoi(second);
            int millisecond_dat = atoi(millisecond);

            if (!((month_dat >= 1) && (month_dat <= 12))){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }
            if (!((day_dat >= 1) && (day_dat <= 31))){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }
            if (!((hour_dat >= 0) && (hour_dat <= 23))){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }
            if (!((minute_dat >= 0) && (minute_dat <= 59))){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }
            if (!((second_dat >= 0) && (second_dat <= 59))){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }
            if (!((millisecond_dat >= 0) && (millisecond_dat <= 999))){
                printf("[Quickserver] Log name is corrupted.\n");
                return 1;
            }

            printf("Log analysis:\n");
            printf("Date:\n");
            printf("  - Month: %d\n", month_dat);
            printf("  - Day: %d\n", day_dat);
            printf("  - Year: %d\n", year_dat);
            printf("Time:\n");
            printf("  - Hour: %d\n", hour_dat);
            printf("  - Minute: %d\n", minute_dat);
            printf("  - Second: %d\n", second_dat);
            printf("  - millisecond: %d\n", millisecond_dat);
            printf("Request data:\n");
            printf("  - Client's ip: %s\n", client_ip_dat);
            printf("  - Request url: '%s'\n", request_url_dat);
            printf("  - Request method: '%s'\n", request_method_dat);
            printf("  - Request headers: '%s'\n", request_headers_dat);
            printf("  - Request body: '%s'\n", request_body_dat);
            return 0;
        }
        else{
            printf("[Quickserver] Invalid number of args.\n");
            printf("[Quickserver] Correct usage (args between square brackets are for https only):\n");
            printf("[Quickserver] quickserver /path/to/serve /path/to/logs port [/path/to/pem /path/to/key]\n");
            printf("[Quickserver] or\n");
            printf("[Quickserver] quickserver help\n");
            printf("[Quickserver] or\n");
            printf("[Quickserver] quickserver analyse-log /path/to/log.json\n");
            printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
            return 1;
        }
    }
    if (argc != 6 && argc != 4){
        printf("[Quickserver] Invalid number of args.\n");
        printf("[Quickserver] Correct usage (args between square brackets are for https only):\n");
        printf("[Quickserver] quickserver /path/to/serve /path/to/logs port [/path/to/pem /path/to/key]\n");
        printf("[Quickserver] or\n");
        printf("[Quickserver] quickserver help\n");
        printf("[Quickserver] or\n");
        printf("[Quickserver] quickserver analyse-log /path/to/log.json\n");
        printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
        return 1;
    }

    char** args = malloc((argc - 1) * sizeof(char*));
    if (!args){
        printf("[Quickserver] Failed to allocate memory to store args.\n");
        return 1;
    }
    
    for (int index = 1; index < argc; index++){
        args[index - 1] = argv[index];
    }
    argc--;

    bool https_enabled = false;

    if (!dir_exists(args[0])){
        printf("[Quickserver] The first argument (path to directory to serve) is not a valid path to a directory.\n");
        printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
        return 1;
    }
    if (!dir_exists(args[1])){
        printf("[Quickserver] The second argument (path to log directory) is not a valid path to a directory.\n");
        printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
        return 1;
    }
    
    int port = atoi(args[2]);
    if (port < 1 || port > 65535){
        printf("[Quickserver] The third argument (port to serve on) is invalid as a valid port is within 1 and 65535 (inclusive).\n");
        printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
        return 1;
    }
    if (argc == 5){
        https_enabled = true;
        if (!is_file(args[3])){
            printf("[Quickserver] The fourth argument (path to pem file, required to create an https server, not to create an http server) is not a path to a valid file.\n");
            printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
            return 1;
        }
        if (!is_file(args[4])){
            printf("[Quickserver] The fifth argument (path to key file, required to create an https server, not to create an http server) is not a path to a valid file.\n");
            printf("[Quickserver] Please run 'quickserver help' for additional help.\n");
            return 1;
        }
        g_tls_cert_data = file_read(args[3]);
        if (!g_tls_cert_data){
            printf("[Quickserver] Failed to read the pem file. Common reasons include: insufficient privileges...\n");
            return 1;
        }
        g_tls_key_data = file_read(args[4]);
        if (!g_tls_key_data){
            printf("[Quickserver] Failed to read the key file. Common reasons include: insufficient privileges...\n");
            free(g_tls_cert_data);
            g_tls_cert_data = NULL;
            return 1;
        }
    }

    struct mg_mgr mgr;
    mg_log_set(MG_LL_NONE);
    mg_mgr_init(&mgr);

    struct mg_connection *lsn;
    if (https_enabled){
        char lsn_addr[strlen("https://[::]:xxxxx") + 1];
        sprintf(lsn_addr, "https://[::]:%d", port);
        lsn = mg_http_listen(&mgr, lsn_addr, qs_http_cb, NULL);
    }
    else{
        char lsn_addr[strlen("http://[::]:xxxxx") + 1];
        sprintf(lsn_addr, "http://[::]:%d", port);
        lsn = mg_http_listen(&mgr, lsn_addr, qs_http_cb, NULL);
    }
    if (lsn == NULL) {
        printf("[Quickserver] Failed to start listening on port %d. Common reasons include: Port already in use, insufficient privileges...\n", port);
        mg_mgr_free(&mgr);
        if (g_tls_cert_data){
            free(g_tls_cert_data);
            g_tls_cert_data = NULL;
        }
        if (g_tls_key_data){
            free(g_tls_key_data);
            g_tls_key_data = NULL;
        }
        return 1;
    }

    if (https_enabled){
        // Enable TLS
        struct mg_tls_opts opts = {
            .cert = mg_str(g_tls_cert_data),
            .key = mg_str(g_tls_key_data),
        };
        mg_tls_init(lsn, &opts);
        if (lsn->tls == NULL || !lsn->is_tls) {
            printf("[Quickserver] Failed to init tls. Common reasons include: invalid pem, invalid key...\n");
            mg_mgr_free(&mgr);
            free(g_tls_cert_data);
            free(g_tls_key_data);
            g_tls_cert_data = NULL;
            g_tls_key_data = NULL;
            return 1;
        }
        g_https_enabled = true;
    }

    while (true){
        mg_mgr_poll(&mgr, 10);
    }

    mg_mgr_free(&mgr);
    if (g_tls_cert_data){
        free(g_tls_cert_data);
        g_tls_cert_data = NULL;
    }
    if (g_tls_key_data){
        free(g_tls_key_data);
        g_tls_key_data = NULL;
    }
    g_https_enabled = false;
}
