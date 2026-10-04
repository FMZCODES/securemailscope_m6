# SecureMailScope M3-M5 Integration

This pack is designed to be added to the existing `E:\securemailscope_m6`
project without replacing the working M2 parser.

## 1. Copy

Copy the `app` folder from this package into:

    E:\securemailscope_m6\

Merge it with the existing `app` folder.

## 2. M5 model

The source repository contains `M5/ml_model.pkl`.

Copy that file into:

    E:\securemailscope_m6\app\analysis\m5\ml_model.pkl

If the model is not copied, M5 still runs, but `ml_model_status` will be
`rule_based_fallback` and the final risk will be rule-based.

## 3. Dependency

M3 requires Scapy:

    python -m pip install scapy

Your existing M2 dependencies remain unchanged.

## 4. Pipeline call

After your current M2 analysis succeeds, call:

    from app.analysis.pipeline import run_m3_m5

    combined = run_m3_m5(uploaded_pcap_path)

The result is:

    combined["m3"]
    combined["m4"]
    combined["m5"]

Do not replace your current M2 code. This pack is an adapter layer around it.

## 5. Important limitation

The original M3 source detects TCP/email streams and STARTTLS from TCP payloads.
The original M4 source expects optional `tls` and `certificate` fields in M3 data,
but the original M3 implementation does not populate those fields.

Therefore this first merge preserves the team's existing M3/M4 contract:
M4 can report missing STARTTLS immediately, while deeper TLS/certificate findings
appear when those fields are supplied by a later packet-enrichment step.

## 6. MongoDB

MongoDB should receive the combined result only after M2-M5 complete.
MongoDB failure should not fail the PCAP analysis endpoint.
