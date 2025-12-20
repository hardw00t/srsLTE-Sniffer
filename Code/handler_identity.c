/**
 * handler_identity.c - Identity extraction handler implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "handler_identity.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*============================================================================
 * Internal State
 *============================================================================*/

static int g_paging_handler_id = -1;
static int g_mib_handler_id = -1;
static int g_sib1_handler_id = -1;
static int g_sib2_handler_id = -1;

/*============================================================================
 * Default Configuration
 *============================================================================*/

void identity_handler_default_config(identity_handler_config_t *config) {
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(identity_handler_config_t));

    config->extract_imsi = true;
    config->extract_stmsi = true;
    config->correlate_identities = true;
    config->track_cells = true;
    config->use_heuristic = true;
    config->log_to_file = false;
    config->log_file = NULL;
    config->log_json = true;
    config->collect_stats = true;
}

/*============================================================================
 * Context Management
 *============================================================================*/

identity_handler_ctx_t *identity_handler_create(void) {
    identity_handler_config_t config;
    identity_handler_default_config(&config);
    return identity_handler_create_ex(&config, NULL);
}

identity_handler_ctx_t *identity_handler_create_ex(
    const identity_handler_config_t *config,
    identity_tracker_t *tracker)
{
    identity_handler_ctx_t *ctx = calloc(1, sizeof(identity_handler_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    if (config != NULL) {
        memcpy(&ctx->config, config, sizeof(identity_handler_config_t));
    } else {
        identity_handler_default_config(&ctx->config);
    }

    if (tracker != NULL) {
        ctx->tracker = tracker;
        ctx->owns_tracker = false;
    } else {
        tracker_config_t tracker_cfg = {
            .max_records = 10000,
            .expiry_seconds = 3600,
            .track_location = ctx->config.track_cells
        };
        ctx->tracker = tracker_create(&tracker_cfg);
        if (ctx->tracker == NULL) {
            free(ctx);
            return NULL;
        }
        ctx->owns_tracker = true;
    }

    memset(&ctx->stats, 0, sizeof(identity_handler_stats_t));

    return ctx;
}

void identity_handler_destroy(identity_handler_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->owns_tracker && ctx->tracker != NULL) {
        tracker_destroy(ctx->tracker);
    }

    if (ctx->config.log_file != NULL && ctx->config.log_to_file) {
        fflush(ctx->config.log_file);
    }

    free(ctx);
}

identity_tracker_t *identity_handler_get_tracker(identity_handler_ctx_t *ctx) {
    return ctx ? ctx->tracker : NULL;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void identity_handler_get_stats(const identity_handler_ctx_t *ctx,
                                 identity_handler_stats_t *stats) {
    if (ctx == NULL || stats == NULL) {
        return;
    }
    memcpy(stats, &ctx->stats, sizeof(identity_handler_stats_t));
}

void identity_handler_reset_stats(identity_handler_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(&ctx->stats, 0, sizeof(identity_handler_stats_t));
}

void identity_handler_print_stats(const identity_handler_ctx_t *ctx, FILE *out) {
    if (ctx == NULL || out == NULL) {
        return;
    }

    const identity_handler_stats_t *s = &ctx->stats;

    fprintf(out, "=== Identity Handler Statistics ===\n");
    fprintf(out, "  Paging messages processed: %lu\n", (unsigned long)s->paging_messages);
    fprintf(out, "  IMSI extracted: %lu\n", (unsigned long)s->imsi_extracted);
    fprintf(out, "  S-TMSI extracted: %lu\n", (unsigned long)s->stmsi_extracted);
    fprintf(out, "  Correlations made: %lu\n", (unsigned long)s->correlations);
    fprintf(out, "  Parse failures: %lu\n", (unsigned long)s->parse_failures);
    fprintf(out, "  Heuristic successes: %lu\n", (unsigned long)s->heuristic_success);
    fprintf(out, "  Unique IMSI: %lu\n", (unsigned long)s->unique_imsi);
    fprintf(out, "  Unique S-TMSI: %lu\n", (unsigned long)s->unique_stmsi);
    fprintf(out, "===================================\n");
}

/*============================================================================
 * Paging Handler Implementation
 *============================================================================*/

void handler_paging_identity(const decoded_data_t *data, void *ctx) {
    if (data == NULL || ctx == NULL) {
        return;
    }

    identity_handler_ctx_t *h = (identity_handler_ctx_t *)ctx;

    if (data->payload == NULL || data->payload_len == 0) {
        return;
    }

    h->stats.paging_messages++;

    /* Parse paging message */
    paging_message_t paging;
    int result = paging_parse_with_context(
        data->payload,
        data->payload_len,
        data->sfn,
        data->sfidx,
        data->cell_id,
        &paging
    );

    if (result != 0 || !paging.valid) {
        h->stats.parse_failures++;

        /* Try heuristic if enabled */
        if (h->config.use_heuristic) {
            imsi_t imsi;
            stmsi_t stmsi;
            bool found_imsi = (paging_find_imsi_heuristic(data->payload, data->payload_len, &imsi) == 0);
            bool found_stmsi = (paging_find_stmsi_heuristic(data->payload, data->payload_len, &stmsi) == 0);

            if (found_imsi || found_stmsi) {
                h->stats.heuristic_success++;

                if (found_imsi && found_stmsi && h->config.correlate_identities) {
                    /* Correlate IMSI + S-TMSI */
                    tracker_correlate(h->tracker, imsi.digits, stmsi.hex_str,
                                      data->cell_id, 0);
                    h->stats.imsi_extracted++;
                    h->stats.stmsi_extracted++;
                    h->stats.correlations++;
                } else {
                    if (found_imsi && h->config.extract_imsi) {
                        tracker_record_imsi(h->tracker, imsi.digits,
                                            data->cell_id, 0);
                        h->stats.imsi_extracted++;
                    }
                    if (found_stmsi && h->config.extract_stmsi) {
                        tracker_record_stmsi(h->tracker, stmsi.hex_str,
                                             data->cell_id, 0);
                        h->stats.stmsi_extracted++;
                    }
                }

                /* Log if enabled */
                if (h->config.log_to_file && h->config.log_file != NULL) {
                    if (h->config.log_json) {
                        fprintf(h->config.log_file,
                            "{\"timestamp\":%lu,\"sfn\":%u,\"cell_id\":%u",
                            (unsigned long)data->timestamp_us, data->sfn, data->cell_id);
                        if (found_imsi) {
                            fprintf(h->config.log_file, ",\"imsi\":\"%s\",\"mcc\":%u,\"mnc\":%u",
                                    imsi.digits, imsi.mcc, imsi.mnc);
                        }
                        if (found_stmsi) {
                            fprintf(h->config.log_file, ",\"stmsi\":\"%s\"", stmsi.hex_str);
                        }
                        fprintf(h->config.log_file, "}\n");
                    } else {
                        time_t t = data->timestamp_us / 1000000;
                        struct tm *tm = localtime(&t);
                        char time_buf[32];
                        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);

                        fprintf(h->config.log_file, "[%s] SFN=%u Cell=%u",
                                time_buf, data->sfn, data->cell_id);
                        if (found_imsi) {
                            fprintf(h->config.log_file, " IMSI=%s (MCC=%u MNC=%u)",
                                    imsi.digits, imsi.mcc, imsi.mnc);
                        }
                        if (found_stmsi) {
                            fprintf(h->config.log_file, " S-TMSI=%s", stmsi.hex_str);
                        }
                        fprintf(h->config.log_file, "\n");
                    }
                    fflush(h->config.log_file);
                }
            }
        }
        return;
    }

    /* Process parsed paging records */
    for (int i = 0; i < paging.num_records; i++) {
        const paging_record_t *rec = &paging.records[i];

        if (rec->id_type == PAGING_ID_IMSI && h->config.extract_imsi) {
            tracker_record_imsi(h->tracker, rec->imsi.digits,
                                data->cell_id, 0);
            h->stats.imsi_extracted++;

            if (h->config.log_to_file && h->config.log_file != NULL) {
                if (h->config.log_json) {
                    fprintf(h->config.log_file,
                        "{\"timestamp\":%lu,\"sfn\":%u,\"cell_id\":%u,"
                        "\"type\":\"IMSI\",\"imsi\":\"%s\",\"mcc\":%u,\"mnc\":%u}\n",
                        (unsigned long)data->timestamp_us, data->sfn, data->cell_id,
                        rec->imsi.digits, rec->imsi.mcc, rec->imsi.mnc);
                }
                fflush(h->config.log_file);
            }

        } else if (rec->id_type == PAGING_ID_STMSI && h->config.extract_stmsi) {
            tracker_record_stmsi(h->tracker, rec->stmsi.hex_str,
                                 data->cell_id, 0);
            h->stats.stmsi_extracted++;

            if (h->config.log_to_file && h->config.log_file != NULL) {
                if (h->config.log_json) {
                    fprintf(h->config.log_file,
                        "{\"timestamp\":%lu,\"sfn\":%u,\"cell_id\":%u,"
                        "\"type\":\"S-TMSI\",\"stmsi\":\"%s\",\"mmec\":%u,\"m_tmsi\":%u}\n",
                        (unsigned long)data->timestamp_us, data->sfn, data->cell_id,
                        rec->stmsi.hex_str, rec->stmsi.mmec, rec->stmsi.m_tmsi);
                }
                fflush(h->config.log_file);
            }
        }
    }
}

/*============================================================================
 * MIB Handler Implementation
 *============================================================================*/

void handler_mib_info(const decoded_data_t *data, void *ctx) {
    if (data == NULL || ctx == NULL) {
        return;
    }

    cell_info_ctx_t *c = (cell_info_ctx_t *)ctx;

    if (data->payload == NULL || data->payload_len < 3) {
        return;
    }

    int result = mib_parse_with_context(
        data->payload,
        data->sfidx & 0x03,  /* SFN offset from lower bits */
        data->nof_ports,
        data->cell_id,
        &c->current_mib
    );

    if (result == 0) {
        c->mib_valid = true;
        c->current_pci = data->cell_id;

        if (c->log_file != NULL) {
            if (c->log_json) {
                char json_buf[512];
                mib_to_json(&c->current_mib, json_buf, sizeof(json_buf));
                fprintf(c->log_file, "%s\n", json_buf);
            } else {
                mib_print(&c->current_mib, c->log_file);
            }
            fflush(c->log_file);
        }
    }
}

/*============================================================================
 * SIB1 Handler Implementation
 *============================================================================*/

void handler_sib1_info(const decoded_data_t *data, void *ctx) {
    if (data == NULL || ctx == NULL) {
        return;
    }

    cell_info_ctx_t *c = (cell_info_ctx_t *)ctx;

    if (data->payload == NULL || data->payload_len == 0) {
        return;
    }

    int result = sib1_parse(data->payload, data->payload_len, &c->current_sib1);

    if (result == 0 && c->current_sib1.valid) {
        c->sib1_valid = true;
        c->current_tac = c->current_sib1.tac;
        c->current_cell_id = c->current_sib1.cell_id;

        if (c->current_sib1.num_plmn_ids > 0) {
            c->current_mcc = c->current_sib1.plmn_ids[0].mcc;
            c->current_mnc = c->current_sib1.plmn_ids[0].mnc;
        }

        if (c->log_file != NULL) {
            if (c->log_json) {
                char json_buf[512];
                sib1_to_json(&c->current_sib1, json_buf, sizeof(json_buf));
                fprintf(c->log_file, "%s\n", json_buf);
            } else {
                sib1_print(&c->current_sib1, c->log_file);
            }
            fflush(c->log_file);
        }
    }
}

/*============================================================================
 * SIB2 Handler Implementation
 *============================================================================*/

void handler_sib2_info(const decoded_data_t *data, void *ctx) {
    if (data == NULL || ctx == NULL) {
        return;
    }

    cell_info_ctx_t *c = (cell_info_ctx_t *)ctx;

    if (data->payload == NULL || data->payload_len == 0) {
        return;
    }

    int result = sib2_parse(data->payload, data->payload_len, &c->current_sib2);

    if (result == 0 && c->current_sib2.valid) {
        c->sib2_valid = true;

        if (c->log_file != NULL) {
            if (c->log_json) {
                char json_buf[512];
                sib2_to_json(&c->current_sib2, json_buf, sizeof(json_buf));
                fprintf(c->log_file, "%s\n", json_buf);
            } else {
                sib2_print(&c->current_sib2, c->log_file);
            }
            fflush(c->log_file);
        }
    }
}

/*============================================================================
 * Handler Registration
 *============================================================================*/

int identity_handler_register_all(identity_handler_ctx_t *ctx) {
    if (ctx == NULL) {
        return -1;
    }

    g_paging_handler_id = data_handler_register(
        DATA_TYPE_PAGING, handler_paging_identity, ctx, "identity_paging");

    if (g_paging_handler_id < 0) {
        return -1;
    }

    return 0;
}

void identity_handler_unregister_all(identity_handler_ctx_t *ctx) {
    (void)ctx;

    if (g_paging_handler_id >= 0) {
        data_handler_unregister(DATA_TYPE_PAGING, g_paging_handler_id);
        g_paging_handler_id = -1;
    }

    if (g_mib_handler_id >= 0) {
        data_handler_unregister(DATA_TYPE_MIB, g_mib_handler_id);
        g_mib_handler_id = -1;
    }

    if (g_sib1_handler_id >= 0) {
        data_handler_unregister(DATA_TYPE_SIB1, g_sib1_handler_id);
        g_sib1_handler_id = -1;
    }

    if (g_sib2_handler_id >= 0) {
        data_handler_unregister(DATA_TYPE_SIB2, g_sib2_handler_id);
        g_sib2_handler_id = -1;
    }
}

/*============================================================================
 * Cell Info Context
 *============================================================================*/

cell_info_ctx_t *cell_info_ctx_create(void) {
    cell_info_ctx_t *ctx = calloc(1, sizeof(cell_info_ctx_t));
    return ctx;
}

void cell_info_ctx_destroy(cell_info_ctx_t *ctx) {
    if (ctx != NULL) {
        free(ctx);
    }
}

void cell_info_print(const cell_info_ctx_t *ctx, FILE *out) {
    if (ctx == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== Current Cell Information ===\n");
    fprintf(out, "  PCI: %u\n", ctx->current_pci);
    fprintf(out, "  TAC: %u (0x%04X)\n", ctx->current_tac, ctx->current_tac);
    fprintf(out, "  Cell ID: %u (0x%07X)\n", ctx->current_cell_id, ctx->current_cell_id);
    fprintf(out, "  PLMN: %03u-%02u\n", ctx->current_mcc, ctx->current_mnc);

    if (ctx->mib_valid) {
        fprintf(out, "  MIB: Valid\n");
        fprintf(out, "    Bandwidth: %.1f MHz (%u RBs)\n",
                ctx->current_mib.bandwidth_mhz, ctx->current_mib.n_rb_dl);
        fprintf(out, "    Antenna Ports: %u\n", ctx->current_mib.nof_ports);
    }

    if (ctx->sib1_valid) {
        fprintf(out, "  SIB1: Valid\n");
        fprintf(out, "    Cell Barred: %s\n",
                ctx->current_sib1.cell_barred ? "Yes" : "No");
    }

    if (ctx->sib2_valid) {
        fprintf(out, "  SIB2: Valid\n");
        fprintf(out, "    Reference Signal Power: %d dBm\n",
                ctx->current_sib2.reference_signal_power);
    }

    fprintf(out, "================================\n");
}
