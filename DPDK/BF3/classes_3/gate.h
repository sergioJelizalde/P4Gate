/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * p4gate/gate.h - the small forest and the gate of P4Gate, in software (the SmartNIC-only implementation of the whole pipeline).
 *
 *   keys  x[0..K+3] = iat_min >> 17, len_max, iat_max >> 24, len_total, llr_k + 0x8000      (what the egress range tables see)
 *   forest          RF_NTREES trees, the DEFER forest of scripts/gen_p4gate_online.py (classes 0..K-1, K = DEFER, leaf score = DEFER probability * 255)
 *   gate            GATE_SCORE: defer when the sum of the leaf scores >= RF_THETA_SCORE        (the ranked P4Gate; the budget is the threshold)
 *                   GATE_VOTES: defer when >= RF_DEFER_VOTES trees vote DEFER
 *                   in both: defer when every tree votes DEFER; otherwise the class is the majority of the non-DEFER votes (the first one in tree order on ties)
 *   NIC model       boosted trees (gbt_model.h) on [len_max, len_total, iat_min, iat_max, llr_k + 0x8000], run only for deferred flows
 */
#ifndef P4GATE_GATE_H
#define P4GATE_GATE_H
#include "core.h"
#include "rf_model.h"

enum { GATE_VOTES = 0, GATE_SCORE = 1 };

struct gate_result {
    uint8_t  cls;          /* 0..K-1 when accepted, RF_DEFER_CLASS when deferred */
    uint8_t  defer;
    uint8_t  n_defer;      /* trees that voted DEFER */
    uint8_t  pad;
    uint16_t score_sum;
};

static inline void gate_keys(const struct flow_state *f, int32_t *x)
{
    x[0] = (int32_t)(f->iat_min >> 17);
    x[1] = (int32_t)f->len_max;
    x[2] = (int32_t)(f->iat_max >> 24);
    x[3] = (int32_t)f->len_total;
    for (int k = 0; k < K_CLASSES; k++) x[4 + k] = (int32_t)(uint16_t)(f->cum[k] + 0x8000u);
}

static inline void nic_features(const struct flow_state *f, float *x)
{
    x[0] = (float)f->len_max;
    x[1] = (float)f->len_total;
    x[2] = (float)f->iat_min;
    x[3] = (float)f->iat_max;
    for (int k = 0; k < K_CLASSES; k++) x[4 + k] = (float)(uint16_t)(f->cum[k] + 0x8000u);
}

/* plain recursive-free traversal of every tree, as predict_tree() of the NIC code base, on the flattened arrays of rf_model.h */
static inline struct gate_result rf_gate(const int32_t *x, int mode)
{
    uint8_t vote[RF_NTREES];
    unsigned score = 0, n_def = 0;
    for (int t = 0; t < RF_NTREES; t++) {
        unsigned n = RF_ROOT[t];
        while (RF_FEAT[n] >= 0) n = (x[RF_FEAT[n]] <= RF_THR[n]) ? RF_LEFT[n] : RF_RIGHT[n];
        vote[t] = RF_CLASS[n];
        score += RF_SCORE[n];
        n_def += (vote[t] == RF_DEFER_CLASS);
    }
    unsigned cnt[K_CLASSES + 1];
    memset(cnt, 0, sizeof(cnt));
    unsigned mx = 0;
    for (int t = 0; t < RF_NTREES; t++) if (vote[t] != RF_DEFER_CLASS) { cnt[vote[t]]++; if (cnt[vote[t]] > mx) mx = cnt[vote[t]]; }
    int kept = -1;
    for (int t = 0; t < RF_NTREES && mx; t++) if (vote[t] != RF_DEFER_CLASS && cnt[vote[t]] == mx) { kept = vote[t]; break; }

    struct gate_result r;
    r.n_defer = (uint8_t)n_def;
    r.score_sum = (uint16_t)score;
    int defer = (kept < 0) || (mode == GATE_SCORE ? score >= RF_THETA_SCORE : n_def >= RF_DEFER_VOTES);
    r.defer = (uint8_t)defer;
    r.cls = (uint8_t)(defer ? RF_DEFER_CLASS : kept);
    r.pad = 0;
    return r;
}
#endif
