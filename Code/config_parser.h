/**
 * config_parser.h - JSON configuration file support
 *
 * Provides a simple JSON parser for configuration files.
 * Uses a lightweight embedded parser (no external dependencies).
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * JSON Value Types
 *============================================================================*/

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

/*============================================================================
 * JSON Value Structure
 *============================================================================*/

#define JSON_MAX_STRING     256
#define JSON_MAX_CHILDREN   64

typedef struct json_value json_value_t;

struct json_value {
    json_type_t type;
    char        key[JSON_MAX_STRING];

    union {
        bool        bool_val;
        double      num_val;
        char        str_val[JSON_MAX_STRING];
        struct {
            json_value_t *items;
            size_t        count;
        } array;
        struct {
            json_value_t *items;
            size_t        count;
        } object;
    } value;
};

/*============================================================================
 * Application Configuration Structure
 *============================================================================*/

#define MAX_FREQUENCIES     16
#define MAX_HANDLER_NAME    32

typedef struct {
    /* Radio settings */
    struct {
        uint32_t frequencies[MAX_FREQUENCIES];
        size_t   num_frequencies;
        float    gain;
        uint16_t rnti;
        float    sample_rate;
    } radio;

    /* Capture settings */
    struct {
        char    output_dir[256];
        bool    enable_json;
        bool    enable_sqlite;
        bool    enable_pcap;
        bool    enable_csv;
    } capture;

    /* Identity tracking */
    struct {
        bool     enabled;
        uint32_t cache_size;
        uint32_t expiry_seconds;
    } tracking;

    /* Logging */
    struct {
        char     file[256];
        char     level[16];
        bool     console;
        bool     file_logging;
        uint64_t max_size;
        bool     rotate;
    } logging;

    /* Web interface */
    struct {
        bool     enabled;
        uint16_t port;
        char     bind_address[64];
    } web;

    /* Database */
    struct {
        char db_path[256];
        bool async_writes;
    } database;

} app_config_t;

/*============================================================================
 * Parsing Functions
 *============================================================================*/

/**
 * Parse JSON string into json_value structure
 * @param json_str      JSON string to parse
 * @param root          Output: root JSON value
 * @return              0 on success, -1 on parse error
 */
int json_parse(const char *json_str, json_value_t *root);

/**
 * Parse JSON file
 * @param filename      Path to JSON file
 * @param root          Output: root JSON value
 * @return              0 on success, -1 on error
 */
int json_parse_file(const char *filename, json_value_t *root);

/**
 * Free JSON value tree
 */
void json_free(json_value_t *value);

/*============================================================================
 * Value Access Functions
 *============================================================================*/

/**
 * Get value by key path (e.g., "radio.frequencies")
 */
json_value_t *json_get(json_value_t *root, const char *path);

/**
 * Get typed values with defaults
 */
bool json_get_bool(json_value_t *root, const char *path, bool default_val);
double json_get_number(json_value_t *root, const char *path, double default_val);
const char *json_get_string(json_value_t *root, const char *path, const char *default_val);
int json_get_int(json_value_t *root, const char *path, int default_val);

/**
 * Get array length
 */
size_t json_array_length(json_value_t *array);

/**
 * Get array element
 */
json_value_t *json_array_get(json_value_t *array, size_t index);

/*============================================================================
 * Application Config Functions
 *============================================================================*/

/**
 * Initialize config with defaults
 */
void config_init_defaults(app_config_t *config);

/**
 * Load configuration from JSON file
 * @param filename      Path to config file
 * @param config        Output: loaded configuration
 * @return              0 on success, -1 on error
 */
int config_load(const char *filename, app_config_t *config);

/**
 * Save configuration to JSON file
 */
int config_save(const char *filename, const app_config_t *config);

/**
 * Print configuration summary
 */
void config_print(const app_config_t *config, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_PARSER_H */
