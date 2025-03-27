#!/bin/sh

# Settings
OUT_DIR="OEM-KEYS"
KEY_SIZE=2048
VALID_KEY_SIZES="2048 4096"
MIN_OPENSSL_VER="1.1.1"
USE_OPENSSL1=0

# Flags
DEBUG=0
DUMP=0
FORCE=0
QUIET=0
USE_ECSDA=1

function parse_args()
{
    while [ $# -gt 0 ]
    do
        case $1 in
        --debug)
            DEBUG=1
            echo "FLAG: Debug: enabled"
            shift
            ;;
        --dump-values)
            DUMP=1
            echo "FLAG: Dumping values: enabled"
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
        --use-rsa)
            USE_ECSDA=0
            echo "FLAG: Use RSA: enabled"
            shift
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
if [ "${DUMP}" -eq 1 ]; then
    hexdump -c ${OUT_DIR}/randfile
fi
log "> Generated."


if [ "${USE_ECSDA}" -eq 1 ]; then
    # Generate ECDSA root key and certificate
    # https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/generate-ecdsa-root-key-and-certificate.html

    log "Generate the ECDSA root key and certificate"

    openssl ecparam -genkey -name secp384r1 -outform PEM -out ${OUT_DIR}/qpsa_rootca.key
    log "> Created ECDSA root key"

    openssl req -new -key ${OUT_DIR}/qpsa_rootca.key -sha384 -out ${OUT_DIR}/rootca_pem.crt \
        -subj '/C=US/CN=Generated OEM Root CA/OU=CDMA Technologies/OU=General Use OEM Key (OEM should update all fields)/L=San Diego/O=SecTools/ST=California' \
        -config opensslroot.cfg -x509 -days 7300 -set_serial 1

    openssl x509 -in ${OUT_DIR}/rootca_pem.crt -inform PEM -out ${OUT_DIR}/qpsa_rootca.cer -outform DER
    log "> Created ECDSA root certificate"

    log "Generate the intermediate certificate authority (CA) key pair and certificate"

    openssl ecparam -genkey -name secp384r1 -outform PEM -out ${OUT_DIR}/qpsa_attestca.key
    log "> Created EC Atrestation CA key"

    openssl req -new -key ${OUT_DIR}/qpsa_attestca.key -out ${OUT_DIR}/ca.csr \
        -subj '/C=US/ST=California/CN=Generated OEM Attestation CA/O=SecTools/L=San Diego' \
        -config opensslroot.cfg -sha384

    openssl x509 -req -in ${OUT_DIR}/ca.csr -CA ${OUT_DIR}/rootca_pem.crt -CAkey ${OUT_DIR}/qpsa_rootca.key \
        -out ${OUT_DIR}/attestca_pem.crt -set_serial 1 -days 7300 -extfile v3.ext -sha384 -CAcreateserial

    openssl x509 -inform PEM -in ${OUT_DIR}/attestca_pem.crt -outform DER -out ${OUT_DIR}/qpsa_attestca.cer
    log "> Created EC Attestation CA certificate"

else
    # Generate RSA CA key pair and certificate
    # https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/generate-rsa-root-ca-key-pair-and-certificate.html

    log "Generate the root CA key pair and certificate"

    openssl genrsa -out ${OUT_DIR}/qpsa_rootca.key ${KEY_SIZE}
    log "> Created RSA root CA key"

    if [ "${USE_OPENSSL1}" -eq 1 ]; then
        # Updated -sha256 to -sha384
        openssl req -new -sha384 -key ${OUT_DIR}/qpsa_rootca.key -x509 -out ${OUT_DIR}/rootca_pem.crt \
            -subj /C=US/ST=California/L="San Diego"/OU="General Use Test Key (for testing 13 only)"/OU="CDMA Technologies"/O=QUALCOMM/CN="QCT Root CA 1" \
            -days 7300 -set_serial 1 -config opensslroot.cfg -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sigopt digest:sha384
    else
        # Dropped "-sigopt digest:sha256" from the original command
        # Updated -sha256 to -sha384
        openssl req -new -sha384 -key ${OUT_DIR}/qpsa_rootca.key -x509 -out ${OUT_DIR}/rootca_pem.crt \
            -subj /C=US/ST=California/L="San Diego"/OU="General Use Test Key (for testing 13 only)"/OU="CDMA Technologies"/O=QUALCOMM/CN="QCT Root CA 1" \
            -days 7300 -set_serial 1 -config opensslroot.cfg -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1
    fi

    openssl x509 -in ${OUT_DIR}/rootca_pem.crt -inform PEM -out ${OUT_DIR}/qpsa_rootca.cer -outform DER
    log "> Created RSA root CA certificate"

    if [ "${DUMP}" -eq 1 ]; then
        openssl x509 -text -inform DER -in ${OUT_DIR}/qpsa_rootca.cer
    fi

    log "Generate the attestation CA key pair and certificate"

    openssl genrsa -out ${OUT_DIR}/qpsa_attestca.key ${KEY_SIZE}
    log "> Created RSA Attestation CA key"

    # Dropped "-days 7300" from original command
    openssl req -new -key ${OUT_DIR}/qpsa_attestca.key -out ${OUT_DIR}/attestca.csr \
        -subj /C=US/ST=CA/L="San Diego"/OU="CDMA Technologies"/O=QUALCOMM/CN="QUALCOMM Attestation CA" -config opensslroot.cfg

    if [ "${USE_OPENSSL1}" -eq 1 ]; then
        openssl x509 -req -in ${OUT_DIR}/attestca.csr -CA ${OUT_DIR}/rootca_pem.crt -CAkey ${OUT_DIR}/qpsa_rootca.key \
            -out ${OUT_DIR}/attestca_pem.crt -set_serial 5 -days 7300 -extfile v3.ext –sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sigopt digest:sha384
    else
        # Dropped: "–sha256" and "- sigopt digest:sha256" from original command
        openssl x509 -req -in ${OUT_DIR}/attestca.csr -CA ${OUT_DIR}/rootca_pem.crt -CAkey ${OUT_DIR}/qpsa_rootca.key \
            -out ${OUT_DIR}/attestca_pem.crt -set_serial 5 -days 7300 -extfile v3.ext -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1
    fi

    openssl x509 -inform PEM -in ${OUT_DIR}/attestca_pem.crt -outform DER -out ${OUT_DIR}/qpsa_attestca.cer
    log "> Created RSA Attestation CA certificate"
fi

# Generate SHA-384 hash for RSA and ECDSA
# https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/generate-sha-384-hash-for-rsa-and-ecdsa.html

log "Generate SHA384 hash for signing"
openssl dgst -sha384 ${OUT_DIR}/qpsa_rootca.cer >${OUT_DIR}/sha384rootcert.txt
log "> Created"


# Clean up

log "Cleaning up"

rm ${OUT_DIR}/randfile
rm ${OUT_DIR}/*.csr
rm ${OUT_DIR}/*.crt

log "> Done"
