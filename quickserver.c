#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

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
    char method[16];
    char* url; //request target including query string
    char* body; //if any else NULL
    char* headers;
} reqData;

typedef struct {
    char* resp_data;
    int http_code;
    char resp_headers[256];
    bool free_authorized;
} reqResp;

char* default_404_page = "<!DOCTYPE html>\n<html>\n    <head>\n        <title>404 – Page not found</title>\n    </head>\n    <body>\n        <iframe id=\"homepage\"></iframe>\n        <div id=\"container\">\n            <center>\n                <h1 id=\"header\">404 – Page not found</h1>\n                <button id=\"button\">Go to homepage</button>\n            </center>\n        </div>\n    </body>\n</html>\n<script>\n    ;(function(){\n        var container = document.getElementById(\"container\");\n        var header = document.getElementById(\"header\");\n        var button = document.getElementById(\"button\");\n        var homepage = document.getElementById(\"homepage\");\n        homepage.style.backgroundColor = \"white\";\n        var original_homepage_dsp = homepage.style.display;\n        homepage.style.display = \"none\";\n        \n        var homepage_loaded = false;\n        homepage.onload = function(){\n            homepage_loaded = true;\n        }\n\n        document.body.style.backgroundColor = \"#f0eee6\";\n        document.body.style.margin = \"0px\";\n\n        document.body.style.userSelect = \"none\";\n        document.body.style.webkitUserSelect = \"none\";\n        document.body.style.mozUserSelect = \"none\";\n        document.body.style.msUserSelect = \"none\";\n\n        container.style.backgroundColor = \"#e3dacc\";\n        container.style.position = \"absolute\";\n        \n        header.style.fontFamily = \"Arial\";\n        button.style.backgroundColor = \"rgb(40,40,40)\";\n        button.style.color = \"rgb(255,255,255)\";\n        button.style.fontFamily = \"Arial\";\n        button.style.border = \"0px\"\n\n        button.onmouseover = function(){\n            button.style.backgroundColor = \"#bcb6ff\";\n            button.style.color = \"rgb(0,0,0)\";\n        }\n        button.onmouseout = function(){\n            button.style.backgroundColor = \"rgb(40,40,40)\";\n            button.style.color = \"rgb(255,255,255)\";\n        }\n\n        window.onresize = function(){\n            var sizeFactor = window.innerWidth * window.innerHeight / 10000;\n\n            header.style.fontSize = sizeFactor / 2 + \"px\";\n            container.style.borderRadius = sizeFactor / 16 + \"px\";\n\n            try{\n                button.style.fontSize = sizeFactor / 3 + \"px\";\n                button.style.borderRadius = sizeFactor / 16 + \"px\";\n            }\n            catch (error){}\n\n            container.style.padding = sizeFactor / 16 + \"px\"\n\n            container.style.marginLeft = window.innerWidth / 2 - container.offsetWidth / 2 + \"px\";\n            container.style.marginTop = window.innerHeight / 2 - container.offsetHeight / 2 + \"px\";\n        }\n        window.onresize();\n\n        var wait = async function(ms){\n            return new Promise(function(resolve, reject){\n                setTimeout(resolve, ms);\n            })\n        }\n\n        button.onclick = async function(){\n            homepage.src = \"/\"\n\n            button.remove();\n            header.innerHTML = \"Loading...\";\n\n            window.onresize();\n\n            while (!homepage_loaded){\n                await wait(10); //wait till page is loaded.\n            }\n\n            homepage.style.display = original_homepage_dsp;\n\n            homepage.style.border = \"0px\";\n            homepage.style.position = \"absolute\";\n            container.remove();\n            window.onresize = function(){\n                homepage.style.width = window.innerWidth + \"px\";\n                homepage.style.height = window.innerHeight + \"px\";\n            }\n            window.onresize();\n        }\n    })();\n</script>\n\n";

char* serve_path = NULL;
char* log_path = NULL;

char *exts_to_mime[][2] = {
    {"7z", "application/x-7z-compressed"},
    {"aac", "audio/aac"},
    {"abw", "application/x-abiword"},
    {"ai", "application/postscript"},
    {"apk", "application/vnd.android.package-archive"},
    {"appimage", "application/x-iso9660-appimage"},
    {"avi", "video/x-msvideo"},
    {"avif", "image/avif"},
    {"azw", "application/vnd.amazon.ebook"},
    {"bak", "application/octet-stream"},
    {"bat", "application/x-msdownload"},
    {"bin", "application/octet-stream"},
    {"bmp", "image/bmp"},
    {"bz", "application/x-bzip"},
    {"bz2", "application/x-bzip2"},
    {"c", "text/x-c"},
    {"cab", "application/vnd.ms-cab-compressed"},
    {"cbr", "application/x-cbr"},
    {"cbz", "application/x-cbz"},
    {"cc", "text/x-c"},
    {"cfg", "text/plain"},
    {"cgi", "application/x-httpd-cgi"},
    {"class", "application/java-vm"},
    {"clj", "text/x-clojure"},
    {"conf", "text/plain"},
    {"cpp", "text/x-c"},
    {"cs", "text/x-csharp"},
    {"css", "text/css"},
    {"csv", "text/csv"},
    {"cxx", "text/x-c"},
    {"deb", "application/vnd.debian.binary-package"},
    {"dll", "application/x-msdownload"},
    {"dmg", "application/x-apple-diskimage"},
    {"doc", "application/msword"},
    {"docm", "application/vnd.ms-word.document.macroenabled.12"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"dot", "application/msword"},
    {"dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
    {"ejs", "application/javascript"},
    {"elf", "application/x-elf"},
    {"eml", "message/rfc822"},
    {"eot", "application/vnd.ms-fontobject"},
    {"epub", "application/epub+zip"},
    {"exe", "application/vnd.microsoft.portable-executable"},
    {"flac", "audio/flac"},
    {"flv", "video/x-flv"},
    {"gif", "image/gif"},
    {"go", "text/plain"},
    {"gz", "application/gzip"},
    {"h", "text/x-c"},
    {"hpp", "text/x-c"},
    {"htm", "text/html"},
    {"html", "text/html"},
    {"ico", "image/x-icon"},
    {"ini", "text/plain"},
    {"iso", "application/x-iso9660-image"},
    {"jar", "application/java-archive"},
    {"jpeg", "image/jpeg"},
    {"jpg", "image/jpeg"},
    {"js", "application/javascript"},
    {"json", "application/json"},
    {"jsonld", "application/ld+json"},
    {"key", "application/x-iwork-keynote-sffkey"},
    {"kt", "text/x-kotlin"},
    {"kts", "text/x-kotlin"},
    {"lha", "application/x-lzh-compressed"},
    {"log", "text/plain"},
    {"lua", "text/x-lua"},
    {"m3u", "audio/x-mpegurl"},
    {"m4a", "audio/mp4"},
    {"m4v", "video/mp4"},
    {"md", "text/markdown"},
    {"mdb", "application/x-msaccess"},
    {"mid", "audio/midi"},
    {"midi", "audio/midi"},
    {"mjs", "application/javascript"},
    {"mkv", "video/x-matroska"},
    {"mov", "video/quicktime"},
    {"mp2", "audio/mpeg"},
    {"mp3", "audio/mpeg"},
    {"mp4", "video/mp4"},
    {"mpeg", "video/mpeg"},
    {"mpg", "video/mpeg"},
    {"msi", "application/x-msdownload"},
    {"odp", "application/vnd.oasis.opendocument.presentation"},
    {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {"odt", "application/vnd.oasis.opendocument.text"},
    {"oga", "audio/ogg"},
    {"ogg", "audio/ogg"},
    {"ogv", "video/ogg"},
    {"otf", "font/otf"},
    {"pdf", "application/pdf"},
    {"php", "application/x-httpd-php"},
    {"pkg", "application/octet-stream"},
    {"pl", "application/x-perl"},
    {"png", "image/png"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"ps", "application/postscript"},
    {"psd", "image/vnd.adobe.photoshop"},
    {"py", "text/x-python"},
    {"rar", "application/vnd.rar"},
    {"rb", "text/x-ruby"},
    {"rpm", "application/x-rpm"},
    {"rs", "text/plain"},
    {"rtf", "application/rtf"},
    {"sass", "text/x-sass"},
    {"scss", "text/x-scss"},
    {"sh", "application/x-sh"},
    {"sql", "application/sql"},
    {"svg", "image/svg+xml"},
    {"svgz", "image/svg+xml"},
    {"swf", "application/x-shockwave-flash"},
    {"tar", "application/x-tar"},
    {"tbz", "application/x-bzip-compressed-tar"},
    {"tbz2", "application/x-bzip-compressed-tar"},
    {"tif", "image/tiff"},
    {"tiff", "image/tiff"},
    {"toml", "application/toml"},
    {"ts", "video/mp2t"},
    {"tsv", "text/tab-separated-values"},
    {"ttf", "font/ttf"},
    {"txt", "text/plain"},
    {"wav", "audio/wav"},
    {"weba", "audio/webm"},
    {"webm", "video/webm"},
    {"webp", "image/webp"},
    {"whl", "application/zip"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},
    {"xls", "application/vnd.ms-excel"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"xml", "application/xml"},
    {"xpi", "application/x-xpinstall"},
    {"xz", "application/x-xz"},
    {"yaml", "application/x-yaml"},
    {"yml", "application/x-yaml"},
    {"zip", "application/zip"},
    {"zst", "application/zstd"},
    {NULL, NULL}
};

char* get_mime_for_ext(char *ext) {
    int low = 0;
    int high = 0;
    while (exts_to_mime[high][0] != NULL) {
        high++;
    }
    high--;
    while (low <= high) {
        int mid = (low + high) / 2;
        int cmp = strcmp(ext, exts_to_mime[mid][0]);
        if (cmp == 0) {
            return exts_to_mime[mid][1];
        } else if (cmp < 0) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    return "application/octet-stream";
}

char** processids = NULL;
int processids_len = 0;

int cmpstr(const void *a, const void *b) {
    char* const *sa = a;
    char* const *sb = b;
    return strcmp(*sa, *sb);
}

void sort_processids(){
    if (processids == NULL){
        return;
    }
    qsort(processids, processids_len, sizeof(char *), cmpstr);
    return;
}

int index_of_processid(char *target) {
    int low = 0;
    int high = processids_len - 1;
    while (low <= high) {
        int mid = (low + high) / 2;
        int cmp = strcmp(processids[mid], target);
        if (cmp == 0) {
            return mid;
        } else {
            if (cmp < 0) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
    }
    return -1;
}

char* newProcessID(){
    char processid[6] = {0};
    while (true){
        for (int index = 0; index < 5; index++){
            processid[index] = '0' + (rand() % 10);
        }

        if (index_of_processid(processid) == -1){
            processids_len++;
            char** tmp = realloc(processids, processids_len * sizeof(char*));
            if (!tmp){
                printf("[Quickserver] Failed to allocate memory to generate new proceessid.\n");
                return NULL;
            }
            processids = tmp;
            processids[processids_len - 1] = malloc(6);
            if (!processids[processids_len - 1]){
                printf("[Quickserver] Failed to allocate memory to generate new processid.\n");
                processids_len--;
                //no need for tmp as scale down cannot ever fail.
                processids = realloc(processids, processids_len * sizeof(char*));
                return NULL;
            }
            strcpy(processids[processids_len - 1], processid);
            sort_processids();
            return processids[index_of_processid(processid)];
        }
    }
}

bool freeProcessId(char* processid){
    printf("[Quickserver] [%s] Freeing processid...\n", processid);
    int indexOfProcessid = index_of_processid(processid);
    if (indexOfProcessid == -1){
        return false;
    }
    char** newprocessids = malloc((processids_len - 1) * sizeof(char*));
    if (!newprocessids){
        printf("[Quickserver] Failed to allocate memory to free processid.\n");
        return false;
    }

    bool offset = false;
    for (int index = 0; index < processids_len; index++){
        if (index == indexOfProcessid){
            free(processids[index]);
            offset = true;
            continue;
        }
        if (offset){
            newprocessids[index - 1] = processids[index];
        }
        else{
            newprocessids[index] = processids[index];
        }
    }

    processids_len--;
    free(processids);
    processids = newprocessids;

    sort_processids();

    return true;
}

void get_time_string(char* buf) {
    struct timeval tv;
    gettimeofday(&tv, NULL);  // seconds + microseconds

    struct tm* tm_info = localtime(&tv.tv_sec);

    int millis = tv.tv_usec / 1000;

    sprintf(buf, "%02d-%02d-%04d_%02d:%02d:%02d:%03d",
             tm_info->tm_mon + 1,
             tm_info->tm_mday,
             tm_info->tm_year + 1900,
             tm_info->tm_hour,
             tm_info->tm_min,
             tm_info->tm_sec,
             millis);
}

#ifdef log
#undef log
#endif

#define log put_to_log
bool put_to_log(reqData log_data, reqResp resp, char* processid){
    printf("[Quickserver] [%s] Generating log...\n", processid);
    char time[32] = {0};
    get_time_string(time);

    char log_name[32] = {0};
    sprintf(log_name, "%s.json", time);

    cJSON* log = cJSON_CreateObject();
    if (!log){
        printf("[Quickserver] [%s] Failed to generate log.\n", processid);
        return false;
    }
    cJSON_AddStringToObject(log, "client_ip", log_data.ip);
    cJSON_AddStringToObject(log, "request_method", log_data.method);
    cJSON_AddStringToObject(log, "request_url", log_data.url);
    if (log_data.body){
        cJSON_AddStringToObject(log, "request_body", log_data.body);
    }
    else{
        cJSON_AddStringToObject(log, "request_body", "");
    }
    if (log_data.headers){
        cJSON_AddStringToObject(log, "request_headers", log_data.headers);
    }
    else{
        cJSON_AddStringToObject(log, "request_headers", "");
    }
    cJSON_AddNumberToObject(log, "response_http_code", resp.http_code);
    cJSON_AddStringToObject(log, "response_headers", resp.resp_headers);

    char* log_str = cJSON_PrintUnformatted(log);
    if (!log_str){
        printf("[Quickserver] [%s] Failed to generate log.\n", processid);
        cJSON_Delete(log);
        return false;
    }
    cJSON_Delete(log);
    printf("[Quickserver] [%s] Generated log.\n", processid);

    int log_path_len = strlen(log_path);
    char log_path_no_leading_slash[log_path_len + 2];
    strcpy(log_path_no_leading_slash, log_path);
    if (log_path_no_leading_slash[log_path_len - 1] == '/'){
        log_path_no_leading_slash[log_path_len - 1] = '\0';
    }
    char log_write_path[strlen(log_path_no_leading_slash) + 32];
    sprintf(log_write_path, "%s/%s", log_path_no_leading_slash, log_name);

    printf("[Quickserver] [%s] Writing log '%s'...\n", processid, log_name);
    bool log_write_success = file_write(log_write_path, log_str);
    free(log_str);
    if (!log_write_success){
        printf("[Quickserver] [%s] Failed to write log '%s'.\n", processid, log_name);
        return false;
    }
    printf("[Quickserver] [%s] Wrote log '%s'.\n", processid, log_name);
    return true;
}

reqResp handle_request(reqData req){
    if (strncmp(req.ip, "::ffff:", strlen("::ffff:")) == 0){
        req.ip_type = true;
        int ip_len = strlen(req.ip);
        char newip[ip_len - strlen("::ffff:") + 1];
        for (int index = strlen("::ffff:"); index < ip_len; index++){
            newip[index - strlen("::ffff:")] = req.ip[index];
        }
        newip[ip_len - strlen("::ffff:")] = '\0';
        strcpy(req.ip, newip);
    }

    reqResp resp = {0};
    printf("[Quickserver] New request received, generating processid...\n");
    char* processid = newProcessID();
    if (!processid){
        printf("[Quickserver] Failed to generate processid.\n");
        //freeProcessid will refuse the processid placeholder as it cannot be in the list
        //it is therefore safe
        processid = "no_processid";
    }
    printf("[Quickserver] [%s] Processid generated.\n", processid);
    printf("[Quickserver] [%s] Client's ip is of type %s and is %s.\n", processid, req.ip_type ? "ipv4" : "ipv6", req.ip);
    printf("[Quickserver] [%s] Request url is '%s'.\n", processid, req.url);
    printf("[Quickserver] [%s] Request method is '%s'.\n", processid, req.method);

    if (strcmp(req.method, "GET") != 0){
        printf("[Quickserver] [%s] Request method is not GET but '%s', sending 405 (method not allowed) error...\n", processid, req.method);
        resp.http_code = 405;
        resp.free_authorized = false;
        resp.resp_data = "Method not allowed (use GET).";
        sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
        printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
        log(req, resp, processid);
        freeProcessId(processid);
        return resp;
    }

    //Resolve path
    int serve_path_len = strlen(serve_path);
    char serve_path_no_leading_slash[serve_path_len + 1];
    strcpy(serve_path_no_leading_slash, serve_path);
    if (serve_path_no_leading_slash[serve_path_len - 1] == '/'){
        serve_path_no_leading_slash[serve_path_len - 1] = '\0';
    }

    //Url can be quite big so we will do heap alloc
    char* full_path = malloc(serve_path_len + strlen(req.url) + 1);
    if (!full_path){
        printf("[Quickserver] [%s] Failed to allocate memory to resolve what the url points to.\n", processid);
        printf("[Quickserver] [%s] Sending 500 (internal server error)...\n", processid);
        resp.http_code = 500;
        resp.free_authorized = false;
        resp.resp_data = "Internal server error.";
        sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
        printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
        log(req, resp, processid);
        freeProcessId(processid);
        return resp;
    }
    
    sprintf(full_path, "%s%s", serve_path_no_leading_slash, req.url); //url starts with /

    bool resolve_type; //false is directory, true is file
    bool is_dir_ = is_dir(full_path);
    bool is_file_ = is_file(full_path);
    if ((!is_dir_) && (!is_file_)){
        printf("[Quickserver] [%s] Request url does not point to a valid file/directory, sending 404 (Not Found)...\n", processid);
        //404 case.
        //Attempt to fetch 404.html
        //Path can be allocated on stack as there is no url.
        printf("[Quickserver] [%s] Attempting to read custom user 404.html (if it exists)...\n", processid);
        char full_path_404[serve_path_len + strlen("/404.html") + 1];
        sprintf(full_path_404, "%s/404.html", serve_path_no_leading_slash);
        char* user_404_page = file_read(full_path_404);
        ssize_t user_404_page_size = file_size(full_path_404);
        if ((!user_404_page) || (user_404_page_size == -1)){
            printf("[Quickserver] [%s] Custom user 404.html does not exist or is unreadable, using default embedded 404.html page...\n", processid);
            resp.http_code = 404;
            resp.free_authorized = false;
            resp.resp_data = default_404_page;
            sprintf(resp.resp_headers, "Content-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(default_404_page));
            printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
            log(req, resp, processid);
            freeProcessId(processid);
            free(full_path);
            return resp;
        }
        else{
            printf("[Quickserver] [%s] Custom user 404.html exists and is readable, using it...\n", processid);
            resp.http_code = 404;
            resp.free_authorized = true;
            resp.resp_data = user_404_page;
            sprintf(resp.resp_headers, "Content-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close", user_404_page_size);
            printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
            log(req, resp, processid);
            freeProcessId(processid);
            free(full_path);
            return resp;
        }
    }
    else{
        resolve_type = is_file_;
    }

    if (resolve_type){
        //if file
        printf("[Quickserver] [%s] Request url points to a valid file, reading it...\n", processid);
        char* file = file_read(full_path);
        ssize_t file_size_ = file_size(full_path);
        if ((!file) || (file_size_ == -1)){
            printf("[Quickserver] [%s] Failed to read file, sending 500 (internal server error)...\n", processid);
            resp.http_code = 500;
            resp.free_authorized = false;
            resp.resp_data = "Internal server error.";
            sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
            printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
            log(req, resp, processid);
            freeProcessId(processid);
            free(full_path);
            return resp;
        }
        printf("[Quickserver] [%s] Read file. (%zu bytes)\n", processid, file_size_);
        printf("[Quickserver] [%s] Identifying file extension...\n", processid);
        char* ext = full_path;
        while ((strstr(ext, "/") != NULL) || (strstr(ext, "\\") != NULL)){
            ext += 1;
        }
        int ext_len = strlen(ext);
        int dot_index = -1;
        for (int index = 0; index < ext_len; index++){
            if (ext[index] == '.'){
                dot_index = index;
                break;
            }
            dot_index++;
        }
        ext += dot_index; //Now ext is either en empty string or the extension of the file
        if (*ext == '.'){
            ext++;
        }
        printf("[Quickserver] [%s] File extension: '.%s'.\n", processid, ext);
        printf("[Quickserver] [%s] Guessing MIME type...\n", processid);

        char* mime = get_mime_for_ext(ext);

        printf("[Quickserver] [%s] MIME type: '%s'\n", processid, mime);
        printf("[Quickserver] [%s] Responding with file, guessed MIME type, and http code 200 (OK)...\n", processid);
        resp.http_code = 200;
        resp.free_authorized = true;
        resp.resp_data = file;
        sprintf(resp.resp_headers, "Content-Type: %s; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close", mime, file_size_);
        printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
        log(req, resp, processid);
        freeProcessId(processid);
        free(full_path);
        return resp;
    }
    else{
        //If directory
        //we wanna remove the leading slash from full_path if there is one to do the manipulation
        printf("[Quickserver] [%s] Request url points to a directory, checking if it contains an 'index.html' file...\n", processid);
        int full_path_len = strlen(full_path);
        if (full_path[full_path_len - 1] == '/'){
            full_path[full_path_len - 1] = '\0';
        }

        //Heap alloc cuz full_path contains url which can be quite fat.
        char* full_path_resolved = malloc(full_path_len + strlen("/index.html") + 1);
        if (!full_path_resolved){
            printf("[Quickserver] [%s] Failed to allocate memory to resolve what the url points to.\n", processid);
            printf("[Quickserver] [%s] Sending 500 (internal server error)...\n", processid);
            resp.http_code = 500;
            resp.free_authorized = false;
            resp.resp_data = "Internal server error.";
            sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
            printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
            log(req, resp, processid);
            freeProcessId(processid);
            free(full_path);
            free(full_path_resolved);
            return resp;
        }
        sprintf(full_path_resolved, "%s/index.html", full_path);
        if (is_file(full_path_resolved)){
            printf("[Quickserver] [%s] The directory the request url points to contains an 'index.html' file, reading it...\n", processid);
            char* file = file_read(full_path_resolved);
            ssize_t file_size_ = file_size(full_path_resolved);

            if ((!file) || (file_size_ == -1)){
                printf("[Quickserver] [%s] Failed to read file, sending 500 (internal server error)...\n", processid);
                resp.http_code = 500;
                resp.free_authorized = false;
                resp.resp_data = "Internal server error.";
                sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
                printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
                log(req, resp, processid);
                freeProcessId(processid);
                free(full_path);
                free(full_path_resolved);
                return resp;
            }

            printf("[Quickserver] [%s] Read file. (%zu bytes)\n", processid, file_size_);
            printf("[Quickserver] [%s] Responding with file, and http code 200 (OK)...\n", processid);
            resp.http_code = 200;
            resp.free_authorized = true;
            resp.resp_data = file;
            sprintf(resp.resp_headers, "Content-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close", file_size_);
            printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
            log(req, resp, processid);
            freeProcessId(processid);
            free(full_path);
            free(full_path_resolved);
            return resp;
        }
        else{
            printf("[Quickserver] [%s] The directory the request url points to does not contain an 'index.html' file, generating list of directory items...\n", processid);
            char** directory_list = dir_list(full_path);
            if (!directory_list){
                printf("[Quickserver] [%s] Failed to list directory, sending 500 (internal server error)...\n", processid);
                resp.http_code = 500;
                resp.free_authorized = false;
                resp.resp_data = "Internal server error.";
                sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
                printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
                log(req, resp, processid);
                freeProcessId(processid);
                free(full_path);
                free(full_path_resolved);
                return resp;
            }
            printf("[Quickserver] [%s] Listed directory, generating response...\n", processid);
            size_t directory_list_response_len = strlen("List of items in '':\n") + strlen(req.url) + 1;
            char* directory_list_response = malloc(directory_list_response_len);
            if (!directory_list_response){
                printf("[Quickserver] [%s] Failed to allocate memory to generate response, sending 500 (internal server error)...\n", processid);
                resp.http_code = 500;
                resp.free_authorized = false;
                resp.resp_data = "Internal server error.";
                sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
                printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
                log(req, resp, processid);
                freeProcessId(processid);
                free(full_path);
                free(full_path_resolved);
                dir_list_free(directory_list);
                return resp;
            }
            sprintf(directory_list_response, "List of items in '%s':\n", req.url);
            
            for (int index = 0; directory_list[index] != NULL; index++){
                directory_list_response_len = directory_list_response_len + strlen("  - \n") + strlen(directory_list[index]);
                char* tmp = realloc(directory_list_response, directory_list_response_len);
                if (!directory_list_response){
                    printf("[Quickserver] [%s] Failed to allocate memory to generate response, sending 500 (internal server error)...\n", processid);
                    resp.http_code = 500;
                    resp.free_authorized = false;
                    resp.resp_data = "Internal server error.";
                    sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", strlen(resp.resp_data));
                    printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
                    log(req, resp, processid);
                    freeProcessId(processid);
                    free(directory_list_response);
                    dir_list_free(directory_list);
                    free(full_path);
                    free(full_path_resolved);
                    return resp;
                }
                directory_list_response = tmp;
                char itemConstruct[strlen("  - \n") + strlen(directory_list[index]) + 1];
                sprintf(itemConstruct, "  - %s\n", directory_list[index]);
                strcat(directory_list_response, itemConstruct);
            }

            directory_list_response[directory_list_response_len - 2] = '\0'; //remove last newline

            printf("[Quickserver] [%s] Generated response, responding with it, and http code 200 (OK).\n", processid);
            resp.http_code = 200;
            resp.free_authorized = true;
            resp.resp_data = directory_list_response;
            sprintf(resp.resp_headers, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close", directory_list_response_len - 2);
            printf("[Quickserver] [%s] Request terminated, logging and serving content...\n", processid);
            log(req, resp, processid);
            freeProcessId(processid);
            free(full_path);
            free(full_path_resolved);
            dir_list_free(directory_list);
            return resp;
        }
    }
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

        // URL (uri + optional query)
        size_t url_len = hm->uri.len;
        if (hm->query.len > 0) {
            url_len += 1 + hm->query.len;
        }
        rd.url = (char*) malloc(url_len + 1);
        if (rd.url == NULL) {
            mg_http_reply(c, 500, "", "Internal Server Error");
            return;
        }
        char *url_ptr = rd.url;
        if (hm->uri.len > 0) {
            memcpy(url_ptr, hm->uri.buf, hm->uri.len);
            url_ptr += hm->uri.len;
        }
        if (hm->query.len > 0) {
            *url_ptr++ = '?';
            memcpy(url_ptr, hm->query.buf, hm->query.len);
            url_ptr += hm->query.len;
        }
        *url_ptr = '\0';

        // Body (malloc + NUL)
        if (hm->body.len > 0) {
            rd.body = (char*) malloc(hm->body.len + 1);
            if (rd.body == NULL) {
                if (rd.url) free(rd.url);
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
            if (rd.url) free(rd.url);
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
        if (rd.url) free(rd.url);
        if (rd.body) free(rd.body);
        if (rd.headers) free(rd.headers);
        if (rr.resp_data && rr.free_authorized) free(rr.resp_data);
    }
}

int main(int argc, char** argv){
    printf("[Quickserver] Quickserver by willmil11 (v1.0 - 10/30/2025 [mm/dd/yyyy]).\n");
    srand(time(NULL));
    if (argc == 2){
        if (strcmp(argv[1], "help") == 0){
            printf("[Quickserver] [Help] Hello, this is a guide on how do use this software which is a webserver written by me willmil11, in C:\n");
            printf("[Quickserver] [Help] Unless you installed it through an automatic stript that did it for you, you need to move it to somewhere in your PATH like '/usr/bin' on linux so you can use it easily.\n");
            printf("[Quickserver] [Help] \n");
            printf("[Quickserver] [Help] Here are the ways to use it:\n");
            printf("[Quickserver] [Help]   - quickserver help\n");
            printf("[Quickserver] [Help]   - quickserver analyse-log /path/to/log.json\n");
            printf("[Quickserver] [Help]   - quickserver /path/to/serve/ /path/to/logs/ port [/path/to/pem] [/path/to/key]\n");
            printf("[Quickserver] [Help] \n");
            printf("[Quickserver] [Help] The first one, it displays the message you can see here, the second one is to display the information of a log file in a human readable way, and the third one is to start the webserver, if you want it to be http do not specify the last two arguments, however if you want it to be https, please do.\n");
            printf("[Quickserver] [Help] \n");
            printf("[Quickserver] [Help] The argument for the second one is the path to the log file which are named like 'month-day-year_hour:minute:second:millisecond'.\n");
            printf("[Quickserver] [Help] The arguments for the third one are firstly, the path to a valid directory containing the content to serve, secondly the path to a valid directory where the logs will be written, thirdly the port to serve on, thirdly and fourth (optional if you want https instead of http) the path to the pem file and key file respectively.\n");
            printf("[Quickserver] [Help] \n");
            printf("[Quickserver] [Help] Also please note that you may need to run with higher privileges (sudo/run as administrator/other things depending on os) the webserver if you're running on privileged ports.\n");
            printf("[Quickserver] [Help] \n");
            printf("[Quickserver] [Help] If you need any more help, you can contact me with my email (willmil111012@gmail.com) or my discord (willmil11).\n");
            printf("[Quickserver] [Help] Good luck and have a good day :)\n");
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
            cJSON* response_http_code = cJSON_GetObjectItem(log, "response_http_code");
            cJSON* response_headers = cJSON_GetObjectItem(log, "response_headers");

            if ((client_ip == NULL) || (request_url == NULL) || (request_headers == NULL) || (request_body == NULL) || (request_method == NULL) || (response_http_code == NULL) || (response_headers == NULL)){
                corrupt_log();
            }

            if ((!cJSON_IsString(client_ip)) || (!cJSON_IsString(request_url)) || (!cJSON_IsString(request_headers)) || (!cJSON_IsString(request_body)) || (!cJSON_IsString(request_method)) || (!(cJSON_IsNumber(response_http_code)) || (!(cJSON_IsString(response_headers))))){
                corrupt_log();
            }

            char* client_ip_dat = strdup(client_ip->valuestring);
            char* request_url_dat = strdup(request_url->valuestring);
            char* request_headers_dat = strdup(request_headers->valuestring);
            char* request_body_dat = strdup(request_body->valuestring);
            char* request_method_dat = strdup(request_method->valuestring);
            int response_http_code_dat = response_http_code->valueint;
            char* response_headers_dat = strdup(response_headers->valuestring);

            if ((!client_ip_dat) || (!request_url_dat) || (!request_headers_dat) || (!request_body_dat) || (!request_method_dat) || (!response_headers_dat)){
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
            printf("Response data:\n");
            printf("  - Response's http code: %d\n", response_http_code_dat);
            printf("  - Response's headers: '%s'\n", response_headers_dat);
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

    serve_path = args[0];
    log_path = args[1];

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
            .cert = mg_str(g_tls_cert_data),   // PEM may include full chain
            .key  = mg_str(g_tls_key_data),
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
    else{
        g_https_enabled = false;
    }

    while (true){
        mg_mgr_poll(&mgr, 1);
    }
}
