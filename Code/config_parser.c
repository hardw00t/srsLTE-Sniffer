/**
 * config_parser.c - JSON configuration parser implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "config_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/*============================================================================
 * Parser State
 *============================================================================*/

typedef struct {
    const char *input;
    size_t      pos;
    size_t      len;
    char        error[256];
} parser_state_t;

/*============================================================================
 * Parser Utilities
 *============================================================================*/

static void skip_whitespace(parser_state_t *p) {
    while (p->pos < p->len && isspace(p->input[p->pos])) {
        p->pos++;
    }
}

static char peek(parser_state_t *p) {
    skip_whitespace(p);
    return (p->pos < p->len) ? p->input[p->pos] : '\0';
}

static char consume(parser_state_t *p) {
    skip_whitespace(p);
    return (p->pos < p->len) ? p->input[p->pos++] : '\0';
}

static bool match(parser_state_t *p, const char *str) {
    skip_whitespace(p);
    size_t len = strlen(str);
    if (p->pos + len <= p->len && strncmp(p->input + p->pos, str, len) == 0) {
        p->pos += len;
        return true;
    }
    return false;
}

/*============================================================================
 * JSON Parsing
 *============================================================================*/

static int parse_value(parser_state_t *p, json_value_t *val);

static int parse_string(parser_state_t *p, char *out, size_t max_len) {
    if (consume(p) != '"') {
        snprintf(p->error, sizeof(p->error), "Expected '\"' at position %zu", p->pos);
        return -1;
    }

    size_t i = 0;
    while (p->pos < p->len && p->input[p->pos] != '"') {
        if (i >= max_len - 1) break;

        if (p->input[p->pos] == '\\' && p->pos + 1 < p->len) {
            p->pos++;
            switch (p->input[p->pos]) {
                case 'n': out[i++] = '\n'; break;
                case 't': out[i++] = '\t'; break;
                case 'r': out[i++] = '\r'; break;
                case '"': out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                default: out[i++] = p->input[p->pos]; break;
            }
        } else {
            out[i++] = p->input[p->pos];
        }
        p->pos++;
    }
    out[i] = '\0';

    if (consume(p) != '"') {
        snprintf(p->error, sizeof(p->error), "Unterminated string at position %zu", p->pos);
        return -1;
    }

    return 0;
}

static int parse_number(parser_state_t *p, double *out) {
    skip_whitespace(p);
    char *end;
    *out = strtod(p->input + p->pos, &end);
    if (end == p->input + p->pos) {
        snprintf(p->error, sizeof(p->error), "Invalid number at position %zu", p->pos);
        return -1;
    }
    p->pos = end - p->input;
    return 0;
}

static int parse_array(parser_state_t *p, json_value_t *val) {
    if (consume(p) != '[') {
        return -1;
    }

    val->type = JSON_ARRAY;
    val->value.array.items = calloc(JSON_MAX_CHILDREN, sizeof(json_value_t));
    val->value.array.count = 0;

    if (peek(p) == ']') {
        consume(p);
        return 0;
    }

    while (val->value.array.count < JSON_MAX_CHILDREN) {
        if (parse_value(p, &val->value.array.items[val->value.array.count]) != 0) {
            return -1;
        }
        val->value.array.count++;

        char c = peek(p);
        if (c == ']') {
            consume(p);
            return 0;
        }
        if (c != ',') {
            snprintf(p->error, sizeof(p->error), "Expected ',' or ']' at position %zu", p->pos);
            return -1;
        }
        consume(p);
    }

    return 0;
}

static int parse_object(parser_state_t *p, json_value_t *val) {
    if (consume(p) != '{') {
        return -1;
    }

    val->type = JSON_OBJECT;
    val->value.object.items = calloc(JSON_MAX_CHILDREN, sizeof(json_value_t));
    val->value.object.count = 0;

    if (peek(p) == '}') {
        consume(p);
        return 0;
    }

    while (val->value.object.count < JSON_MAX_CHILDREN) {
        json_value_t *item = &val->value.object.items[val->value.object.count];

        /* Parse key */
        if (parse_string(p, item->key, JSON_MAX_STRING) != 0) {
            return -1;
        }

        /* Expect colon */
        if (consume(p) != ':') {
            snprintf(p->error, sizeof(p->error), "Expected ':' at position %zu", p->pos);
            return -1;
        }

        /* Parse value */
        if (parse_value(p, item) != 0) {
            return -1;
        }
        val->value.object.count++;

        char c = peek(p);
        if (c == '}') {
            consume(p);
            return 0;
        }
        if (c != ',') {
            snprintf(p->error, sizeof(p->error), "Expected ',' or '}' at position %zu", p->pos);
            return -1;
        }
        consume(p);
    }

    return 0;
}

static int parse_value(parser_state_t *p, json_value_t *val) {
    char c = peek(p);

    if (c == '"') {
        val->type = JSON_STRING;
        return parse_string(p, val->value.str_val, JSON_MAX_STRING);
    }
    if (c == '{') {
        return parse_object(p, val);
    }
    if (c == '[') {
        return parse_array(p, val);
    }
    if (c == '-' || isdigit(c)) {
        val->type = JSON_NUMBER;
        return parse_number(p, &val->value.num_val);
    }
    if (match(p, "true")) {
        val->type = JSON_BOOL;
        val->value.bool_val = true;
        return 0;
    }
    if (match(p, "false")) {
        val->type = JSON_BOOL;
        val->value.bool_val = false;
        return 0;
    }
    if (match(p, "null")) {
        val->type = JSON_NULL;
        return 0;
    }

    snprintf(p->error, sizeof(p->error), "Unexpected character '%c' at position %zu", c, p->pos);
    return -1;
}

/*============================================================================
 * Public API
 *============================================================================*/

int json_parse(const char *json_str, json_value_t *root) {
    if (!json_str || !root) return -1;

    parser_state_t parser = {
        .input = json_str,
        .pos = 0,
        .len = strlen(json_str),
        .error = {0}
    };

    memset(root, 0, sizeof(json_value_t));

    int ret = parse_value(&parser, root);
    if (ret != 0) {
        fprintf(stderr, "JSON parse error: %s\n", parser.error);
    }
    return ret;
}

int json_parse_file(const char *filename, json_value_t *root) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open config file: %s\n", strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    size_t read = fread(buffer, 1, size, fp);
    buffer[read] = '\0';
    fclose(fp);

    int ret = json_parse(buffer, root);
    free(buffer);
    return ret;
}

void json_free(json_value_t *value) {
    if (!value) return;

    switch (value->type) {
        case JSON_ARRAY:
            if (value->value.array.items) {
                for (size_t i = 0; i < value->value.array.count; i++) {
                    json_free(&value->value.array.items[i]);
                }
                free(value->value.array.items);
            }
            break;
        case JSON_OBJECT:
            if (value->value.object.items) {
                for (size_t i = 0; i < value->value.object.count; i++) {
                    json_free(&value->value.object.items[i]);
                }
                free(value->value.object.items);
            }
            break;
        default:
            break;
    }
}

json_value_t *json_get(json_value_t *root, const char *path) {
    if (!root || !path) return NULL;

    char key[JSON_MAX_STRING];
    const char *dot = strchr(path, '.');

    if (dot) {
        size_t len = dot - path;
        if (len >= JSON_MAX_STRING) return NULL;
        strncpy(key, path, len);
        key[len] = '\0';
    } else {
        strncpy(key, path, JSON_MAX_STRING - 1);
        key[JSON_MAX_STRING - 1] = '\0';
    }

    if (root->type != JSON_OBJECT) return NULL;

    for (size_t i = 0; i < root->value.object.count; i++) {
        if (strcmp(root->value.object.items[i].key, key) == 0) {
            if (dot) {
                return json_get(&root->value.object.items[i], dot + 1);
            }
            return &root->value.object.items[i];
        }
    }

    return NULL;
}

bool json_get_bool(json_value_t *root, const char *path, bool default_val) {
    json_value_t *val = json_get(root, path);
    if (val && val->type == JSON_BOOL) {
        return val->value.bool_val;
    }
    return default_val;
}

double json_get_number(json_value_t *root, const char *path, double default_val) {
    json_value_t *val = json_get(root, path);
    if (val && val->type == JSON_NUMBER) {
        return val->value.num_val;
    }
    return default_val;
}

const char *json_get_string(json_value_t *root, const char *path, const char *default_val) {
    json_value_t *val = json_get(root, path);
    if (val && val->type == JSON_STRING) {
        return val->value.str_val;
    }
    return default_val;
}

int json_get_int(json_value_t *root, const char *path, int default_val) {
    return (int)json_get_number(root, path, (double)default_val);
}

size_t json_array_length(json_value_t *array) {
    if (array && array->type == JSON_ARRAY) {
        return array->value.array.count;
    }
    return 0;
}

json_value_t *json_array_get(json_value_t *array, size_t index) {
    if (array && array->type == JSON_ARRAY && index < array->value.array.count) {
        return &array->value.array.items[index];
    }
    return NULL;
}

/*============================================================================
 * Application Config
 *============================================================================*/

void config_init_defaults(app_config_t *config) {
    memset(config, 0, sizeof(app_config_t));

    /* Radio defaults */
    config->radio.frequencies[0] = 1845000000;
    config->radio.num_frequencies = 1;
    config->radio.gain = 40.0f;
    config->radio.rnti = 0xfffe;
    config->radio.sample_rate = 1.92e6f;

    /* Capture defaults */
    strcpy(config->capture.output_dir, "./output");
    config->capture.enable_json = true;
    config->capture.enable_sqlite = true;
    config->capture.enable_pcap = true;
    config->capture.enable_csv = true;

    /* Tracking defaults */
    config->tracking.enabled = true;
    config->tracking.cache_size = 10000;
    config->tracking.expiry_seconds = 86400;  /* 24 hours */

    /* Logging defaults */
    strcpy(config->logging.file, "srslte_sniffer.log");
    strcpy(config->logging.level, "info");
    config->logging.console = true;
    config->logging.file_logging = false;
    config->logging.max_size = 10 * 1024 * 1024;
    config->logging.rotate = true;

    /* Web defaults */
    config->web.enabled = false;
    config->web.port = 8080;
    strcpy(config->web.bind_address, "127.0.0.1");

    /* Database defaults */
    strcpy(config->database.db_path, "captures.db");
    config->database.async_writes = true;
}

int config_load(const char *filename, app_config_t *config) {
    config_init_defaults(config);

    json_value_t root;
    if (json_parse_file(filename, &root) != 0) {
        return -1;
    }

    /* Radio settings */
    json_value_t *freqs = json_get(&root, "radio.frequencies");
    if (freqs && freqs->type == JSON_ARRAY) {
        config->radio.num_frequencies = 0;
        for (size_t i = 0; i < freqs->value.array.count && i < MAX_FREQUENCIES; i++) {
            json_value_t *f = &freqs->value.array.items[i];
            if (f->type == JSON_NUMBER) {
                config->radio.frequencies[config->radio.num_frequencies++] = (uint32_t)f->value.num_val;
            }
        }
    }
    config->radio.gain = (float)json_get_number(&root, "radio.gain", config->radio.gain);
    config->radio.rnti = (uint16_t)json_get_int(&root, "radio.rnti", config->radio.rnti);

    /* Capture settings */
    const char *dir = json_get_string(&root, "capture.output_dir", NULL);
    if (dir) strncpy(config->capture.output_dir, dir, sizeof(config->capture.output_dir) - 1);
    config->capture.enable_json = json_get_bool(&root, "capture.enable_json", config->capture.enable_json);
    config->capture.enable_sqlite = json_get_bool(&root, "capture.enable_sqlite", config->capture.enable_sqlite);
    config->capture.enable_pcap = json_get_bool(&root, "capture.enable_pcap", config->capture.enable_pcap);
    config->capture.enable_csv = json_get_bool(&root, "capture.enable_csv", config->capture.enable_csv);

    /* Tracking */
    config->tracking.enabled = json_get_bool(&root, "tracking.enabled", config->tracking.enabled);
    config->tracking.cache_size = (uint32_t)json_get_int(&root, "tracking.cache_size", config->tracking.cache_size);
    config->tracking.expiry_seconds = (uint32_t)json_get_int(&root, "tracking.expiry_seconds", config->tracking.expiry_seconds);

    /* Logging */
    const char *log_file = json_get_string(&root, "logging.file", NULL);
    if (log_file) strncpy(config->logging.file, log_file, sizeof(config->logging.file) - 1);
    const char *log_level = json_get_string(&root, "logging.level", NULL);
    if (log_level) strncpy(config->logging.level, log_level, sizeof(config->logging.level) - 1);
    config->logging.console = json_get_bool(&root, "logging.console", config->logging.console);
    config->logging.file_logging = json_get_bool(&root, "logging.file_logging", config->logging.file_logging);

    /* Web */
    config->web.enabled = json_get_bool(&root, "web.enabled", config->web.enabled);
    config->web.port = (uint16_t)json_get_int(&root, "web.port", config->web.port);

    /* Database */
    const char *db_path = json_get_string(&root, "database.db_path", NULL);
    if (db_path) strncpy(config->database.db_path, db_path, sizeof(config->database.db_path) - 1);

    json_free(&root);
    return 0;
}

int config_save(const char *filename, const app_config_t *config) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"radio\": {\n");
    fprintf(fp, "    \"frequencies\": [");
    for (size_t i = 0; i < config->radio.num_frequencies; i++) {
        fprintf(fp, "%u%s", config->radio.frequencies[i],
                i + 1 < config->radio.num_frequencies ? ", " : "");
    }
    fprintf(fp, "],\n");
    fprintf(fp, "    \"gain\": %.1f,\n", config->radio.gain);
    fprintf(fp, "    \"rnti\": %u\n", config->radio.rnti);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"capture\": {\n");
    fprintf(fp, "    \"output_dir\": \"%s\",\n", config->capture.output_dir);
    fprintf(fp, "    \"enable_json\": %s,\n", config->capture.enable_json ? "true" : "false");
    fprintf(fp, "    \"enable_sqlite\": %s,\n", config->capture.enable_sqlite ? "true" : "false");
    fprintf(fp, "    \"enable_pcap\": %s,\n", config->capture.enable_pcap ? "true" : "false");
    fprintf(fp, "    \"enable_csv\": %s\n", config->capture.enable_csv ? "true" : "false");
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"tracking\": {\n");
    fprintf(fp, "    \"enabled\": %s,\n", config->tracking.enabled ? "true" : "false");
    fprintf(fp, "    \"cache_size\": %u,\n", config->tracking.cache_size);
    fprintf(fp, "    \"expiry_seconds\": %u\n", config->tracking.expiry_seconds);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"logging\": {\n");
    fprintf(fp, "    \"file\": \"%s\",\n", config->logging.file);
    fprintf(fp, "    \"level\": \"%s\",\n", config->logging.level);
    fprintf(fp, "    \"console\": %s,\n", config->logging.console ? "true" : "false");
    fprintf(fp, "    \"file_logging\": %s\n", config->logging.file_logging ? "true" : "false");
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"web\": {\n");
    fprintf(fp, "    \"enabled\": %s,\n", config->web.enabled ? "true" : "false");
    fprintf(fp, "    \"port\": %u,\n", config->web.port);
    fprintf(fp, "    \"bind_address\": \"%s\"\n", config->web.bind_address);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"database\": {\n");
    fprintf(fp, "    \"db_path\": \"%s\",\n", config->database.db_path);
    fprintf(fp, "    \"async_writes\": %s\n", config->database.async_writes ? "true" : "false");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return 0;
}

void config_print(const app_config_t *config, FILE *out) {
    fprintf(out, "=== Configuration ===\n");
    fprintf(out, "Radio:\n");
    fprintf(out, "  Frequencies: ");
    for (size_t i = 0; i < config->radio.num_frequencies; i++) {
        fprintf(out, "%u ", config->radio.frequencies[i]);
    }
    fprintf(out, "\n");
    fprintf(out, "  Gain: %.1f\n", config->radio.gain);
    fprintf(out, "  RNTI: 0x%04x\n", config->radio.rnti);

    fprintf(out, "Capture:\n");
    fprintf(out, "  Output dir: %s\n", config->capture.output_dir);
    fprintf(out, "  JSON: %s, SQLite: %s, PCAP: %s, CSV: %s\n",
            config->capture.enable_json ? "on" : "off",
            config->capture.enable_sqlite ? "on" : "off",
            config->capture.enable_pcap ? "on" : "off",
            config->capture.enable_csv ? "on" : "off");

    fprintf(out, "Tracking:\n");
    fprintf(out, "  Enabled: %s\n", config->tracking.enabled ? "yes" : "no");
    fprintf(out, "  Cache size: %u\n", config->tracking.cache_size);

    fprintf(out, "Logging:\n");
    fprintf(out, "  Level: %s\n", config->logging.level);
    fprintf(out, "  Console: %s, File: %s\n",
            config->logging.console ? "on" : "off",
            config->logging.file_logging ? "on" : "off");

    fprintf(out, "====================\n");
}
