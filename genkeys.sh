#!/bin/sh

# Break on errors
set -e

# Settings
OUT_DIR="OEM-KEYS"
KEY_SIZE=2048
VALID_KEY_SIZES="2048 4096"
MIN_OPENSSL_VER="1.1.1"
USE_OPENSSL1=0
ROOT_CERT_TOTALNUM=4
ROOT_CERT_SUBJECT="/CN=OEM Root CA ###/O=SecTools/OU=OEM Key/L=San Diego/ST=California/C=US"
CA_CERT_SUBJECT="/CN=OEM Attestation CA ###/O=SecTools/OU=OEM Key/L=San Diego/ST=California/C=US"

# Flags
DEBUG=0
FORCE=0
QUIET=0
USE_ECSDA=1

function parse_args()
{
    while [ $# -gt 0 ]
    do
        case $1 in
        --ca-cert-subject)
            CA_CERT_SUBJECT=$2
            echo "FLAG: CA_CERT_SUBJECT: ${CA_CERT_SUBJECT}"
            shift
            shift
            ;;
        --debug)
            DEBUG=1
            echo "FLAG: Debug: enabled"
            shift
            ;;
        --force)
            FORCE=1
            echo "FLAG: Force overwrite: enabled"
            shift
            ;;
        --key-size)
            found=0
            for value in ${VALID_KEY_SIZES}; do
                if [ "$2" == "${value}" ]; then
                    KEY_SIZE=$2
                    echo "FLAG: KEY_SIZE=${KEY_SIZE}"
                    found=1
                    break
                fi
            done
            if [ "${found}" -eq 0 ]; then
                echo "Invalid key size: $2.  Valid values: 2048 or 4096.  Aborting."
                exit 1
            fi
            shift
            shift
            ;;
        --quiet)
            QUIET=1
            echo "FLAG: Quiet mode"
            shift
            ;;
        --root-cert-subject)
            ROOT_CERT_SUBJECT=$2
            echo "FLAG: ROOT_CERT_SUBJECT: ${ROOT_CERT_SUBJECT}"
            shift
            shift
            ;;
        --root-cert-totalnum)
            case $2 in
                1 | 2 | 3 | 4)
                    ROOT_CERT_TOTALNUM=$2
                    echo "FLAG: ROOT_CERT_TOTALNUM: ${ROOT_CERT_TOTALNUM}"
                    ;;
                *)
                    echo >&2 "ERROR: ROOT_CERT_TOTALNUM values can be 1,2,3 or 4: $2.  Aborting."
                    exit 1
                    ;;
            esac
            shift
            shift
            ;;
        --use-rsa)
            USE_ECSDA=0
            echo "FLAG: Use RSA: enabled"
            shift
            ;;
        --help)
            echo "Usage parameters:"
            echo "--ca-cert-subject: subject data for CA cert(s)."
            echo "  Make sure to use quotes and place ### where the key # should go."
            echo "--debug: enables debug logging"
            echo "--force: force overwrite files (dangerous!)"
            echo "--key-size: set RSA key size to 2048 or 4096"
            echo "--quiet: disable normal logging"
            echo "--root-cert-subject: subject data for root cert(s)"
            echo "  Make sure to use quotes and place ### where the key # should go."
            echo "--root-cert-totalnum: set # of root certs to use. 1-4 allowed (default: 4)"
            echo "--use-rsa: Use RSA instead of ECDSA for generating keys (default: use ECDSA)"
            exit 0
            ;;
        *)
            shift
            ;;
        esac
    done
}

parse_args "$@"

function debug_log()
{
    if [ "${DEBUG}" -eq 1 ]; then
        echo "DEBUG: $1"
    fi
}

function log()
{
    if [ "${QUIET}" -ne 1 ]; then
        echo "$1"
    fi
}

function version_greater_equal()
{
    printf '%s\n%s\n' "$2" "$1" | sort --check=quiet --version-sort
}


# Checks

log "Check for openssl"
command -v openssl >/dev/null 2>&1 || { echo >&2 "Missing openssl command.  Aborting."; exit 1; }
log "> openssl found."

OPENSSL_VERSION=$(openssl version | cut -d' ' -f2)
log "Check openssl version (${OPENSSL_VERSION}) >= ${MIN_OPENSSL_VER}"
version_greater_equal "${OPENSSL_VERSION}" ${MIN_OPENSSL_VER} || { echo >&2 "Need at least openssl ${MIN_OPENSSL_VER}.  Aborting."; exit 1; }
log "> openssl version == ${OPENSSL_VERSION}"
if [ "$(echo ${OPENSSL_VERSION} | cut -c1)" -eq 1 ]; then
    USE_OPENSSL1=1
    echo "> Using OpenSSL 1.x commands"
fi

log "Check for ${OUT_DIR} directory"
if [ ! -d "${OUT_DIR}" ]; then
    log "> Creating ${OUT_DIR} directory"
    mkdir ${OUT_DIR}
else
    log "> Found ${OUT_DIR} directory"
fi

log "Checking for existing keys"
KEYS_FOUND=0
ls ${OUT_DIR}/*.key >/dev/null 2>&1 && KEYS_FOUND=1
ls ${OUT_DIR}/*.crt >/dev/null 2>&1 && KEYS_FOUND=1
if [ "${KEYS_FOUND}" -eq 1 ]; then
    if [ "${FORCE}" -eq 1 ]; then
        echo "> Force flag enabled: overwriting existing keys!"
    else
        echo "> Existing keys found.  Aborting."
        exit 1
    fi
else
    echo "> No keys found.  Proceeding."
fi


# Generate a randfile

log "Generating randfile"
dd if=/dev/urandom of=${OUT_DIR}/randfile bs=256 count=1 > /dev/null 2>&1
log "> Generated."


key=0
# Loop through ROOT_CERT_TOTALNUM
while [ "${key}" -lt ${ROOT_CERT_TOTALNUM} ]
do
    if [ "${USE_ECSDA}" -eq 1 ]; then

        # Generate ECDSA root key and certificate
        # https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/generate-ecdsa-root-key-and-certificate.html

        log "Generate the ECDSA root ${key} key and certificate"

        openssl ecparam -genkey -name secp384r1 -outform PEM -out ${OUT_DIR}/qpsa_rootca${key}.key
        log "> Created ECDSA root ${key} key"

        openssl req -new -key ${OUT_DIR}/qpsa_rootca${key}.key -sha384 -out ${OUT_DIR}/rootca${key}_pem.crt \
            -subj "$(echo "${ROOT_CERT_SUBJECT}" | sed "s/###/${key}/g")" \
            -config opensslroot.cfg -x509 -days 7300 -set_serial 1

        openssl x509 -in ${OUT_DIR}/rootca${key}_pem.crt -inform PEM -out ${OUT_DIR}/qpsa_rootca${key}.cer -outform DER
        log "> Created ECDSA root ${key} certificate"

        log "Generate the intermediate certificate authority (CA) ${key} key and certificate"

        openssl ecparam -genkey -name secp384r1 -outform PEM -out ${OUT_DIR}/qpsa_attestca${key}.key
        log "> Created EC Atrestation CA ${key} key"

        openssl req -new -key ${OUT_DIR}/qpsa_attestca${key}.key -out ${OUT_DIR}/ca${key}.csr \
            -subj "$(echo "${CA_CERT_SUBJECT}" | sed "s/###/${key}/g")" \
            -config opensslroot.cfg -sha384

        openssl x509 -req -in ${OUT_DIR}/ca${key}.csr -CA ${OUT_DIR}/rootca${key}_pem.crt -CAkey ${OUT_DIR}/qpsa_rootca${key}.key \
            -out ${OUT_DIR}/attestca${key}_pem.crt -set_serial 1 -days 7300 -extfile v3.ext -sha384 -CAcreateserial

        openssl x509 -inform PEM -in ${OUT_DIR}/attestca${key}_pem.crt -outform DER -out ${OUT_DIR}/qpsa_attestca${key}.cer
        log "> Created EC Attestation CA ${key} certificate"

    else
        # Generate RSA CA key pair and certificate
        # https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/generate-rsa-root-ca-key-pair-and-certificate.html

        log "Generate the root CA ${key} key and certificate"

        openssl genrsa -out ${OUT_DIR}/qpsa_rootca${key}.key ${KEY_SIZE}
        log "> Created RSA root CA ${key} key"

        if [ "${USE_OPENSSL1}" -eq 1 ]; then
            # Updated -sha256 to -sha384
            openssl req -new -sha384 -key ${OUT_DIR}/qpsa_rootca${key}.key -x509 -out ${OUT_DIR}/rootca_pem${key}.crt \
                -subj "$(echo "${ROOT_CERT_SUBJECT}" | sed "s/###/${key}/g")" \
                -days 7300 -set_serial 1 -config opensslroot.cfg -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sigopt digest:sha384
        else
            # Dropped "-sigopt digest:sha256" from the original command
            # Updated -sha256 to -sha384
            openssl req -new -sha384 -key ${OUT_DIR}/qpsa_rootca${key}.key -x509 -out ${OUT_DIR}/rootca_pem${key}.crt \
                -subj "$(echo "${ROOT_CERT_SUBJECT}" | sed "s/###/${key}/g")" \
                -days 7300 -set_serial 1 -config opensslroot.cfg -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1
        fi

        openssl x509 -in ${OUT_DIR}/rootca_pem${key}.crt -inform PEM -out ${OUT_DIR}/qpsa_rootca${key}.cer -outform DER
        log "> Created RSA root CA certificate"

        log "Generate the attestation CA ${key} key and certificate"

        openssl genrsa -out ${OUT_DIR}/qpsa_attestca${key}.key ${KEY_SIZE}
        log "> Created RSA Attestation CA ${key} key"

        # Dropped "-days 7300" from original command
        # Added -sha384
        openssl req -new -key ${OUT_DIR}/qpsa_attestca${key}.key -out ${OUT_DIR}/attestca${key}.csr \
            -subj "$(echo "${CA_CERT_SUBJECT}" | sed "s/###/${key}/g")" \
            -config opensslroot.cfg -sha384

        if [ "${USE_OPENSSL1}" -eq 1 ]; then
            # Updated -sha256 to -sha384
            openssl x509 -req -in ${OUT_DIR}/attestca${key}.csr -CA ${OUT_DIR}/rootca_pem${key}.crt -CAkey ${OUT_DIR}/qpsa_rootca${key}.key \
                -out ${OUT_DIR}/attestca${key}_pem.crt -sha384 -set_serial 5 -days 7300 -extfile v3.ext -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sigopt digest:sha256
        else
            # Dropped: "- sigopt digest:sha256" from original command
            # Updated -sha256 to -sha384
            openssl x509 -req -in ${OUT_DIR}/attestca${key}.csr -CA ${OUT_DIR}/rootca_pem${key}.crt -CAkey ${OUT_DIR}/qpsa_rootca${key}.key \
                -out ${OUT_DIR}/attestca${key}_pem.crt -sha384 -set_serial 5 -days 7300 -extfile v3.ext -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1
        fi

        openssl x509 -inform PEM -in ${OUT_DIR}/attestca${key}_pem.crt -outform DER -out ${OUT_DIR}/qpsa_attestca${key}.cer
        log "> Created RSA Attestation CA ${key} certificate"
    fi

    # increment key counter
    key=$((key + 1))
done

# Generate SHA-384 hash for RSA and ECDSA
# https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/generate-sha-384-hash-for-rsa-and-ecdsa.html

log "Generate SHA384 hash for signing"
key=0
rm -rf ${OUT_DIR}/qpsa_roots.bin
# Loop through ROOT_CERT_TOTALNUM
while [ "${key}" -lt ${ROOT_CERT_TOTALNUM} ]
do
    debug_log "> Adding root ${key} cert"
    cat ${OUT_DIR}/qpsa_rootca${key}.cer >> ${OUT_DIR}/qpsa_roots.bin

    # increment key counter
    key=$((key + 1))
done
openssl dgst -sha384 ${OUT_DIR}/qpsa_roots.bin >${OUT_DIR}/sha384_roots_hash.txt
log "> Created"


# Clean up

log "Cleaning up"

rm ${OUT_DIR}/randfile
rm ${OUT_DIR}/*.csr

log "> Done"
