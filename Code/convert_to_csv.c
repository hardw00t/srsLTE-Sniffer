/**
 * convert_to_csv.c - Converts captured IMSI data to CSV format
 *
 * Parses imsi.txt and extracts:
 * - IMSI (MCC + MNC + MSIN)
 * - S-TMSI (MMEC + M-TMSI) when present in same frame
 *
 * Fixed issues:
 * - Empty line crash at file start
 * - S-TMSI parsing after IMSI
 * - Memory leak from getline()
 * - Added proper error handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>

/**
 * Print IMSI portion to CSV with quotes
 */
void print_imsi(FILE *csv, const char payload[], int index, int len, bool end) {
    if (index < 0 || len <= 0) return;

    fprintf(csv, "\"");
    for (int i = 0; i < len && payload[index + i] != '\0'; i++) {
        fprintf(csv, "%c", payload[index + i]);
    }
    fprintf(csv, "\"");
    if (!end) {
        fprintf(csv, ";");
    }
}

/**
 * Check if a substring at given position looks like valid S-TMSI
 * S-TMSI is 10 hex characters (40 bits = MMEC[8] + M-TMSI[32])
 * Returns true if valid hex string that's not purely decimal
 */
bool is_valid_stmsi(const char *payload, int start, int payload_len) {
    if (start < 0 || start + 10 > payload_len) {
        return false;
    }

    bool has_hex_letter = false;
    for (int i = 0; i < 10; i++) {
        char c = payload[start + i];
        if (!isxdigit(c)) {
            return false;
        }
        // Check for hex letters (a-f, A-F) to distinguish from IMSI (decimal only)
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            has_hex_letter = true;
        }
    }

    // S-TMSI typically contains some hex letters
    // Pure decimal strings might be part of another IMSI
    return has_hex_letter;
}

/**
 * Extract S-TMSI from payload at given position
 */
void extract_stmsi(const char *payload, int start, char *stmsi_out) {
    strncpy(stmsi_out, payload + start, 10);
    stmsi_out[10] = '\0';
}

/**
 * Find IMSI in payload
 * IMSI format: [9][5][MCC-rest][MNC][MSIN][8]
 * - Starts with '9' marker
 * - MCC starts with 5 (countries 500-599)
 * - Ends with '8' marker
 * - Contains only decimal digits
 *
 * Returns true if found, sets imsi_index and imsi_length
 */
bool find_imsi(const char *payload, int payload_len, int *imsi_index, int *imsi_length) {
    for (int i = 0; i < payload_len - 16; i++) {
        // Check for IMSI pattern: [9][5][xx][MNC != 00][...][8]
        if (payload[i] == '9' && payload[i + 1] == '5' &&
            !(payload[i + 2] == '0' && payload[i + 3] == '0') &&  // MCC not 500x
            !(payload[i + 4] == '0' && payload[i + 5] == '0') &&  // MNC not 00
            !(payload[i + 6] == '0' && payload[i + 7] == '0' &&
              payload[i + 8] == '0' && payload[i + 9] == '0')) {  // Not all zeros

            // Find the '8' terminator at position 15 or 16
            for (int j = 16; j >= 15; j--) {
                if (i + j < payload_len && payload[i + j] == '8') {
                    // Verify all characters between are digits
                    bool all_digits = true;
                    for (int k = i + 1; k < i + j; k++) {
                        if (!isdigit(payload[k])) {
                            all_digits = false;
                            break;
                        }
                    }

                    if (all_digits) {
                        *imsi_index = i + 1;  // Skip the '9' marker
                        *imsi_length = j - 1; // Exclude the '8' terminator
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

int main(void) {
    FILE *fp = NULL;
    FILE *csv = NULL;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int line_count = 0;
    int imsi_count = 0;

    // Open input file
    fp = fopen("imsi.txt", "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: Cannot open imsi.txt: %s\n", strerror(errno));
        return 1;
    }

    // Open output file
    csv = fopen("imsi.csv", "w");
    if (csv == NULL) {
        fprintf(stderr, "Error: Cannot create imsi.csv: %s\n", strerror(errno));
        fclose(fp);
        return 1;
    }

    // Write CSV header
    fprintf(csv, "\"IMSI\";\"Timestamp\";\"Country\";\"Operator\";\"MSIN\";\"S-TMSI\"\n");

    while ((read = getline(&line, &len, fp)) != -1) {
        line_count++;

        // Skip empty lines and lines with only whitespace
        if (read <= 1) {
            continue;
        }

        // Trim trailing newline/carriage return
        while (read > 0 && (line[read - 1] == '\n' || line[read - 1] == '\r')) {
            line[read - 1] = '\0';
            read--;
        }

        // Skip if line is now empty
        if (read <= 0 || strlen(line) == 0) {
            continue;
        }

        // Verify line contains semicolon separator (timestamp;payload format)
        char *semicolon = strchr(line, ';');
        if (semicolon == NULL) {
            fprintf(stderr, "Warning: Skipping malformed line %d (no semicolon)\n", line_count);
            continue;
        }

        // Make working copies
        char *read_line = strdup(line);
        if (read_line == NULL) {
            fprintf(stderr, "Error: Memory allocation failed at line %d\n", line_count);
            continue;
        }

        // Extract payload (everything after first semicolon)
        char *payload = semicolon + 1;
        int payload_len = strlen(payload);

        if (payload_len < 16) {
            // Payload too short to contain IMSI
            free(read_line);
            continue;
        }

        // Find IMSI in payload
        int imsi_index = 0;
        int imsi_length = 0;

        if (!find_imsi(payload, payload_len, &imsi_index, &imsi_length)) {
            free(read_line);
            continue;
        }

        // Bounds check
        if (imsi_index < 0 || imsi_index + imsi_length > payload_len) {
            fprintf(stderr, "Warning: Invalid IMSI bounds at line %d\n", line_count);
            free(read_line);
            continue;
        }

        // Extract timestamp (everything before first semicolon)
        *semicolon = '\0';  // Temporarily terminate at semicolon
        char *timestamp = read_line;

        // Write IMSI fields to CSV
        print_imsi(csv, payload, imsi_index, imsi_length, false);      // Full IMSI
        fprintf(csv, "\"%s\";", timestamp);                             // Timestamp
        print_imsi(csv, payload, imsi_index, 3, false);                // MCC (3 digits)
        print_imsi(csv, payload, imsi_index + 3, 2, false);            // MNC (2 digits)
        print_imsi(csv, payload, imsi_index + 5, imsi_length - 5, false); // MSIN (rest)

        // Look for S-TMSI before and/or after IMSI
        char s_tmsi_before[11] = {0};
        char s_tmsi_after[11] = {0};
        bool found_before = false;
        bool found_after = false;

        // Check for S-TMSI BEFORE IMSI
        // S-TMSI would be at position (imsi_index - 11) accounting for the '9' marker
        // The full pattern is: [S-TMSI (10)][9][IMSI][8]
        int before_pos = imsi_index - 11;  // 10 chars + separator
        if (before_pos >= 0 && is_valid_stmsi(payload, before_pos, payload_len)) {
            extract_stmsi(payload, before_pos, s_tmsi_before);
            found_before = true;
        }

        // Check for S-TMSI AFTER IMSI
        // After IMSI+terminator, skip any padding zeros
        int after_pos = imsi_index + imsi_length + 1;  // +1 for '8' terminator

        // Skip padding zeros and other markers
        while (after_pos < payload_len &&
               (payload[after_pos] == '0' || payload[after_pos] == '8')) {
            after_pos++;
        }

        if (is_valid_stmsi(payload, after_pos, payload_len)) {
            extract_stmsi(payload, after_pos, s_tmsi_after);
            found_after = true;
        }

        // Write S-TMSI field
        fprintf(csv, "\"");
        if (found_before) {
            fprintf(csv, "%s", s_tmsi_before);
            if (found_after) {
                fprintf(csv, ", ");
            }
        }
        if (found_after) {
            fprintf(csv, "%s", s_tmsi_after);
        }
        fprintf(csv, "\"\n");

        imsi_count++;
        free(read_line);
    }

    // Cleanup
    fclose(fp);
    fclose(csv);

    // Free the line buffer allocated by getline
    if (line) {
        free(line);
        line = NULL;
    }

    printf("Processed %d lines, extracted %d IMSI records to imsi.csv\n",
           line_count, imsi_count);

    return 0;
}
