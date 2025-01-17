#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2023 Merqury Cybersecurity Ltd <info@merqury.eu>
# SPDX-License-Identifier: AGPL-3.0-only



ADDR=${ETSI_014_REF_IMPL_IP_ADDR}:${ETSI_014_REF_IMPL_PORT_NUM}/api/v1/keys

if [ -z "$2" ]; then
    echo "No key id supplied. The key id is required as " \
         "the second command line argument."
    exit
fi

if [ "$1" = "GET" ]; then
    # Description:
    #
    # Calls the 'dec_keys' route using the GET method, specifying the key ID to
    # retrieve.
    #
    # /api/v1/keys/{master_SAE_ID}/dec_keys
    #
    # In this example, 'sae_002' is the slave SAE, because we are using its
    # certificates when calling the end-point. In this call, we are requesting
    # keys with the 'master_SAE_ID' of 'sae_001' based on the URL called.
    #
    # Parameter description:
    #
    #   key_ID: [Optional] The ID of the requested key.

    curl                                  \
        -i                                \
        --tlsv1.3                         \
        --cacert "${CERTS_DIR}"/root.crt  \
        --key "${CERTS_DIR}"/sae_002.key  \
        --cert "${CERTS_DIR}"/sae_002.crt \
        "https://${ADDR}/sae_001/dec_keys?key_ID=${2}"
    echo
elif [ "$1" = "POST" ]; then
    # Description:
    #
    # Calls the 'dec_keys' route using the GET method, specifying the key ID to
    # retrieve.
    #
    # /api/v1/keys/{master_SAE_ID}/dec_keys
    #
    # In this example, 'sae_002' is the slave SAE, because we are using its
    # certificates when calling the end-point. In this call, we are requesting
    # keys with the 'master_SAE_ID' of 'sae_001' based on the URL called.
    #
    # Parameter description:
    #
    #   key_IDs: [Optional] A list of key_IDs to retrieve.
    shift;
    KEYS=()
    for K in "$@"; do
        KEYS+=('{ "key_ID": "'$K'" }')
    done;
    JSON='{"key_IDs": [ '$(IFS=','; echo "${KEYS[*]}")" ]}";
    curl                                          \
        --tlsv1.3                                 \
        --cacert "${CERTS_DIR}"/root.crt          \
        --key "${CERTS_DIR}"/sae_002.key          \
        --cert "${CERTS_DIR}"/sae_002.crt         \
        --header "Content-Type: application/json" \
        --data-raw "${JSON}"                      \
        "https://${ADDR}/sae_001/dec_keys"
    echo
else
    echo "The method to use must be given as a command line parameter."
    echo "Supported parameters are 'GET' or 'POST'."
fi
