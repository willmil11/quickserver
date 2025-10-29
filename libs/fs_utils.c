bool file_exists(const char* path) {
    FILE* f = fopen(path, "r");
    if (f == NULL) {
        return false;
    } else {
        fclose(f);
        return true;
    }
}

bool is_file(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    } else {
        if (S_ISREG(st.st_mode)) {
            return true;
        } else {
            return false;
        }
    }
}

bool is_dir(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    } else {
        if (S_ISDIR(st.st_mode)) {
            return true;
        } else {
            return false;
        }
    }
}

bool file_create(const char* path) {
    FILE* f = fopen(path, "w");
    if (f == NULL) {
        return false;
    } else {
        fclose(f);
        return true;
    }
}

bool file_delete(const char* path) {
    if (remove(path) == 0) {
        return true;
    } else {
        return false;
    }
}

bool file_write(const char* path, const char* content) {
    FILE* f = fopen(path, "w");
    if (f == NULL) {
        return false;
    } else {
        size_t len = strlen(content);
        size_t written = fwrite(content, 1, len, f);
        fclose(f);
        if (written == len) {
            return true;
        } else {
            return false;
        }
    }
}

bool file_append(const char* path, const char* content) {
    FILE* f = fopen(path, "a");
    if (f == NULL) {
        return false;
    } else {
        size_t len = strlen(content);
        size_t written = fwrite(content, 1, len, f);
        fclose(f);
        if (written == len) {
            return true;
        } else {
            return false;
        }
    }
}

ssize_t file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return (ssize_t)st.st_size;
    } else {
        return -1;
    }
}

char* file_read(const char* path) {
    FILE* f = fopen(path, "r");
    if (f == NULL) {
        return NULL;
    } else {
        if (fseek(f, 0, SEEK_END) != 0) {
            fclose(f);
            return NULL;
        }
        long size = ftell(f);
        if (size < 0) {
            fclose(f);
            return NULL;
        }
        rewind(f);
        char* buf = malloc(size + 1);
        if (buf == NULL) {
            fclose(f);
            return NULL;
        }
        size_t read_bytes = fread(buf, 1, size, f);
        buf[read_bytes] = '\0';
        fclose(f);
        return buf;
    }
}

bool dir_create(const char* path) {
    if (mkdir(path, 0755) == 0) {
        return true;
    } else {
        return false;
    }
}

bool dir_delete(const char* path) {
    if (rmdir(path) == 0) {
        return true;
    } else {
        return false;
    }
}

char** dir_list(const char* path) {
    DIR* d = opendir(path);
    if (d == NULL) {
        return NULL;
    } else {
        struct dirent* entry;
        char** list = NULL;
        size_t count = 0;
        while (true) {
            entry = readdir(d);
            if (entry == NULL) {
                break;
            } else {
                char** tmp = realloc(list, sizeof(char*) * (count + 2));
                if (tmp == NULL) {
                    closedir(d);
                    if (list != NULL) {
                        for (size_t i = 0; list[i] != NULL; i++) {
                            free(list[i]);
                        }
                        free(list);
                    }
                    return NULL;
                }
                list = tmp;
                list[count] = strdup(entry->d_name);
                if (list[count] == NULL) {
                    closedir(d);
                    for (size_t i = 0; i < count; i++) {
                        free(list[i]);
                    }
                    free(list);
                    return NULL;
                }
                count = count + 1;
            }
        }
        if (list != NULL) {
            list[count] = NULL;
        }
        closedir(d);
        return list;
    }
}

void dir_list_free(char** list) {
    if (list == NULL) {
        return;
    } else {
        for (size_t i = 0; list[i] != NULL; i++) {
            free(list[i]);
        }
        free(list);
    }
}

bool dir_exists(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    } else {
        if (S_ISDIR(st.st_mode)) {
            return true;
        } else {
            return false;
        }
    }
}

