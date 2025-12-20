/**
 * test_config_parser.c - Tests for configuration parser
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "config_parser.h"
#include <string.h>
#include <unistd.h>

/*============================================================================
 * Tests
 *============================================================================*/

TEST(json_parse_simple_object) {
    const char *json = "{\"name\": \"test\", \"value\": 42}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));
    ASSERT_EQ(JSON_OBJECT, root.type);

    ASSERT_STR_EQ("test", json_get_string(&root, "name", NULL));
    ASSERT_EQ(42, json_get_int(&root, "value", 0));

    json_free(&root);
}

TEST(json_parse_nested_object) {
    const char *json = "{\"outer\": {\"inner\": \"value\"}}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    ASSERT_STR_EQ("value", json_get_string(&root, "outer.inner", NULL));

    json_free(&root);
}

TEST(json_parse_array) {
    const char *json = "{\"numbers\": [1, 2, 3, 4, 5]}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    json_value_t *arr = json_get(&root, "numbers");
    ASSERT_NOT_NULL(arr);
    ASSERT_EQ(JSON_ARRAY, arr->type);
    ASSERT_EQ(5, json_array_length(arr));

    json_value_t *elem = json_array_get(arr, 0);
    ASSERT_NOT_NULL(elem);
    ASSERT_EQ(JSON_NUMBER, elem->type);
    ASSERT_EQ(1, (int)elem->value.num_val);

    json_free(&root);
}

TEST(json_parse_bool) {
    const char *json = "{\"enabled\": true, \"disabled\": false}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    ASSERT_TRUE(json_get_bool(&root, "enabled", false));
    ASSERT_FALSE(json_get_bool(&root, "disabled", true));

    json_free(&root);
}

TEST(json_parse_null) {
    const char *json = "{\"nothing\": null}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    json_value_t *val = json_get(&root, "nothing");
    ASSERT_NOT_NULL(val);
    ASSERT_EQ(JSON_NULL, val->type);

    json_free(&root);
}

TEST(json_parse_string_escapes) {
    const char *json = "{\"text\": \"line1\\nline2\\ttab\"}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    const char *text = json_get_string(&root, "text", NULL);
    ASSERT_NOT_NULL(text);
    ASSERT_NOT_NULL(strchr(text, '\n'));
    ASSERT_NOT_NULL(strchr(text, '\t'));

    json_free(&root);
}

TEST(json_get_default_values) {
    const char *json = "{}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    ASSERT_STR_EQ("default", json_get_string(&root, "missing", "default"));
    ASSERT_EQ(42, json_get_int(&root, "missing", 42));
    ASSERT_EQ(3.14, json_get_number(&root, "missing", 3.14));
    ASSERT_TRUE(json_get_bool(&root, "missing", true));

    json_free(&root);
}

TEST(json_empty_array) {
    const char *json = "{\"items\": []}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    json_value_t *arr = json_get(&root, "items");
    ASSERT_NOT_NULL(arr);
    ASSERT_EQ(0, json_array_length(arr));

    json_free(&root);
}

TEST(json_empty_object) {
    const char *json = "{\"data\": {}}";
    json_value_t root;

    ASSERT_EQ(0, json_parse(json, &root));

    json_value_t *obj = json_get(&root, "data");
    ASSERT_NOT_NULL(obj);
    ASSERT_EQ(JSON_OBJECT, obj->type);

    json_free(&root);
}

TEST(config_init_defaults) {
    app_config_t config;
    config_init_defaults(&config);

    ASSERT_EQ(1, config.radio.num_frequencies);
    ASSERT_EQ(1845000000, config.radio.frequencies[0]);
    ASSERT_EQ(0xfffe, config.radio.rnti);
    ASSERT_TRUE(config.capture.enable_json);
    ASSERT_TRUE(config.tracking.enabled);
    ASSERT_FALSE(config.web.enabled);
}

TEST(config_load_save) {
    const char *test_file = "/tmp/test_config.json";

    /* Create config */
    app_config_t config;
    config_init_defaults(&config);
    config.radio.frequencies[0] = 1900000000;
    config.radio.gain = 50.0f;
    config.web.enabled = true;
    config.web.port = 9000;

    /* Save to file */
    ASSERT_EQ(0, config_save(test_file, &config));

    /* Load from file */
    app_config_t loaded;
    ASSERT_EQ(0, config_load(test_file, &loaded));

    /* Verify */
    ASSERT_EQ(1900000000, loaded.radio.frequencies[0]);
    ASSERT_FLOAT_EQ(50.0, loaded.radio.gain, 0.1);
    ASSERT_TRUE(loaded.web.enabled);
    ASSERT_EQ(9000, loaded.web.port);

    unlink(test_file);
}

TEST(config_load_missing_file) {
    app_config_t config;

    /* Should fail but not crash */
    int result = config_load("/tmp/nonexistent_config_file.json", &config);
    ASSERT_NE(0, result);
}

TEST(json_invalid_syntax) {
    json_value_t root;

    /* Missing closing brace */
    ASSERT_NE(0, json_parse("{\"key\": \"value\"", &root));

    /* Missing quote */
    ASSERT_NE(0, json_parse("{key: \"value\"}", &root));
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_config_parser_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== Config Parser Tests ===" ANSI_RESET "\n");

    RUN_TEST(json_parse_simple_object);
    RUN_TEST(json_parse_nested_object);
    RUN_TEST(json_parse_array);
    RUN_TEST(json_parse_bool);
    RUN_TEST(json_parse_null);
    RUN_TEST(json_parse_string_escapes);
    RUN_TEST(json_get_default_values);
    RUN_TEST(json_empty_array);
    RUN_TEST(json_empty_object);
    RUN_TEST(config_init_defaults);
    RUN_TEST(config_load_save);
    RUN_TEST(config_load_missing_file);
    RUN_TEST(json_invalid_syntax);
}
