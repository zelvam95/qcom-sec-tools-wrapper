#!/bin/sh

# Break on errors
set -e

# Settings
VERSION="0.1"
KEYS_PATH="OEM-KEYS"
KEYS_ROOT_CERT="qpsa_rootca###.cer"
KEYS_CA_CERT="qpsa_attestca###.cer"
KEYS_CA_KEY="qpsa_attestca###.key"
KEYS_ROOTS_HASH="sha384_roots_hash.txt"
ROOT_CERT_TOTALNUM=1
SIGNING_KEY_INDEX=0
IMAGE_DIR="."
OUT_DIR="./signed_images"
ANTI_ROLLBACK_VERSION=0x0
SECTOOL=""
SECURITY_PROFILE=""
PACKAGE_FILENAME=""
FUSE_OEM_HW_ID=""
FUSE_OEM_PRODUCT_ID=""
FUSE_SEC_KEY_DERIVATION_KEY="0x00"

# Flags
DEBUG=0
FORCE=0
QUIET=0
CREATE_SEC_ELF=0

function parse_args()
{
    while [ $# -gt 0 ]
    do
        case $1 in
        --anti-rollback-version)
            if echo "$2" | grep -Eq '^0x?[0-9a-fA-F]+$'; then
                ANTI_ROLLBACK_VERSION=$2
                echo "FLAG: ANTI_ROLLBACK_VERSION: ${ANTI_ROLLBACK_VERSION}"
            else
                echo >&2 "ERROR: ANTI_ROLLBACK_VERSION is not a valid hex number: $2.  Aborting."
                exit 1
            fi
            shift
            shift
            ;;
        --create-sec-elf)
            CREATE_SEC_ELF=1
            echo "FLAG: Create sec.elf: enabled"
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
        --fuse-oem-hw-id)
            if echo "$2" | grep -Eq '^0x?[0-9a-fA-F]+$'; then
                FUSE_OEM_HW_ID=$2
                echo "FLAG: FUSE_OEM_HW_ID: ${FUSE_OEM_HW_ID}"
            else
                echo >&2 "ERROR: FUSE_OEM_HW_ID is not a valid hex number: $2.  Aborting."
                exit 1
            fi
            shift
            shift
            ;;
        --fuse-oem-product-id)
            if echo "$2" | grep -Eq '^0x?[0-9a-fA-F]+$'; then
                FUSE_OEM_PRODUCT_ID=$2
                echo "FLAG: FUSE_OEM_PRODUCT_ID: ${FUSE_OEM_PRODUCT_ID}"
            else
                echo >&2 "ERROR: FUSE_OEM_PRODUCT_ID is not a valid hex number: $2.  Aborting."
                exit 1
            fi
            shift
            shift
            ;;
        --fuse-sec-key-derivation-key)
            if echo "$2" | grep -Eq '^0x?[0-9a-fA-F]+$'; then
                FUSE_SEC_KEY_DERIVATION_KEY=$2
                echo "FLAG: FUSE_SEC_KEY_DERIVATION_KEY: ${FUSE_SEC_KEY_DERIVATION_KEY}"
            else
                echo >&2 "ERROR: FUSE_SEC_KEY_DERIVATION_KEY is not a valid hex number: $2.  Aborting."
                exit 1
            fi
            shift
            shift
            ;;
        --keys-path)
            KEYS_PATH=$2
            echo "FLAG: KEYS_PATH: ${KEYS_PATH}"
            shift
            shift
            ;;
        --keys-root-cert-filename)
            KEYS_ROOT_CERT=$2
            echo "FLAG: KEYS_ROOT_CERT: ${KEYS_ROOT_CERT}"
            shift
            shift
            ;;
        --keys-ca-cert-filename)
            KEYS_CA_CERT=$2
            echo "FLAG: KEYS_CA_CERT: ${KEYS_CA_CERT}"
            shift
            shift
            ;;
        --keys-ca-key-filename)
            KEYS_CA_KEY=$2
            echo "FLAG: KEYS_CA_KEY: ${KEYS_CA_KEY}"
            shift
            shift
            ;;
        --keys-root-hash-filename)
            KEYS_ROOTS_HASH=$2
            echo "FLAG: KEYS_ROOTS_HASH: ${KEYS_ROOTS_HASH}"
            shift
            shift
            ;;
        --image-dir)
            IMAGE_DIR=$2
            echo "FLAG: IMAGE_DIR: ${IMAGE_DIR}"
            shift
            shift
            ;;
        --out-dir)
            OUT_DIR=$2
            echo "FLAG: OUT_DIR: ${OUT_DIR}"
            shift
            shift
            ;;
        --package-filename)
            PACKAGE_FILENAME=$2
            echo "FLAG: PACKAGE_FILENAME: ${PACKAGE_FILENAME}"
            shift
            shift
            ;;
        --quiet)
            QUIET=1
            echo "FLAG: Quiet mode"
            shift
            ;;
        --root-cert-totalnum)
            case $2 in
                1)
                    ROOT_CERT_TOTALNUM=$2
                    echo "FLAG: ROOT_CERT_TOTALNUM: ${ROOT_CERT_TOTALNUM}"
                    ;;
                *)
                    echo >&2 "ERROR: ROOT_CERT_TOTALNUM values can only be 1.  Aborting."
                    exit 1
                    ;;
            esac
            shift
            shift
            ;;
        --sectoolv2)
            SECTOOL=$2
            echo "FLAG: SECTOOL: ${SECTOOL}"
            shift
            shift
            ;;
        --security-profile)
            SECURITY_PROFILE=$2
            echo "FLAG: SECURITY_PROFILE: ${SECURITY_PROFILE}"
            shift
            shift
            ;;
        --signing-key-index)
            case $2 in
                0 | 1 | 2 | 3)
                    SIGNING_KEY_INDEX=$2
                    echo "FLAG: SIGNING_KEY_INDEX: ${SIGNING_KEY_INDEX}"
                    ;;
                *)
                    echo >&2 "ERROR: SIGNING_KEY_INDEX values can be 0,1,2 or 3: $2.  Aborting."
                    exit 1
                    ;;
            esac
            shift
            shift
            ;;
        --version)
            echo "Version: ${VERSION}"
            exit 0
            ;;
        --help)
            echo "Usage parameters:"
            echo "--anti-rollback-version: hex value supplied to 'sectoolsv2 secure-image' --anti-rollback-version param"
            echo "  (default: ${ANTI_ROLLBACK_VERSION})"
            echo "--create-sec-elf: generates a sec.elf file in the OUT_DIR.  Requires --oem-id and --oem-product-id"
            echo "--debug: enables debug logging"
            echo "--force: force overwrite files (dangerous!)"
            echo "--fuse-oem-hw-id: hex value passed to 'sectoolsv2 fuse-blower' --fuse-oem-hw-id param"
            echo "--fuse-oem-product-id: hex value passed to 'sectoolsv2 fuse-blower' --fuse-oem-product-id param"
            echo "--fuse-sec-key-derivation-key: hex value passed to 'sectoolsv2 fuse-blower' --fuse-sec-key-derivation-key param"
            echo "--keys-path: path to keys directory generated by genkeys script (default: ${KEYS_PATH}"
            echo "--keys-root-cert-filename: root cert filename (default: ${KEYS_ROOT_CERT})"
            echo "--keys-ca-cert-filename: ca cert filename (default: ${KEYS_CA_CERT})"
            echo "--keys-ca-key-filename: ca key filename (default: ${KEYS_CA_KEY})"
            echo "--keys-root-hash-filename: roots hash filename (default: ${KEYS_ROOTS_HASH})"
            echo "--image-dir: in file location for images to be signed: *.elf and *.mbn (default: ${IMAGE_DIR})"
            echo "--out-dir: output directory for signed images (default: ${OUT_DIR})"
            echo "--package-filename: output filename, if set will create a .zip package of all standard files + signed images for distribution"
            echo "--quiet: disable normal logging"
            echo "--root-cert-totalnum: set # of root certs to use. 1-4 allowed (default: 4)"
            echo "--sectoolv2: path to sectoolv2 binary"
            echo "--security-profile: path to *-security-profile.xml"
            echo "--signing-key-index: which CA key index to use for signing (default: ${SIGNING_KEY_INDEX})"
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

if [ ! -z "${PACKAGE_FILENAME}" ]; then
    log "Check for zip command"
    command -v zip >/dev/null 2>&1 || { echo >&2 "Missing zip command.  Aborting."; exit 1; }
    log "> zip command found."

    log "Check for existing zip package: ${PACKAGE_FILENAME}"
    if [ -f "${PACKAGE_FILENAME}"  ]; then
        if [ "${FORCE}" -eq 1 ]; then
            log "> Force flag enabled: overwriting existing zip package!"
        else
            echo >&2 "ERROR: Existing zip package Found.  Aborting."
            exit 1
        fi
    else
        log "> No zip package found.  Proceeding."
    fi
fi

[ -z "${SECTOOL}"  ] && { echo >&2 "ERROR: Missing --sectoolv2 parameter.  Aborting."; exit 1; }
[ -z "${SECURITY_PROFILE}"  ] && { echo >&2 "ERROR: Missing --security-profile parameter.  Aborting."; exit 1; }
[ ! -f "${SECURITY_PROFILE}"  ] && { echo >&2 "ERROR: File for security-profile could not be found: ${SECURITY_PROFILE}  Aborting."; exit 1; }
[ ! -d "${KEYS_PATH}"  ] && { echo >&2 "ERROR: Directory for KEYS_PATH is not found: ${KEYS_PATH}.  Use --keys-path to set.  Aborting."; exit 1; }

if [ "${CREATE_SEC_ELF}" -eq 1 ]; then
    if [ -z "${FUSE_OEM_HW_ID}" ]; then
        echo >&2 "ERROR: --fuse-oem-hw-id must be set when --create-sec-elf is enabled.  Aborting."
        exit 1
    fi
    if [ -z "${FUSE_OEM_PRODUCT_ID}" ]; then
        echo >&2 "ERROR: --fuse-oem-product-id must be set when --create-sec-elf is enabled.  Aborting."
        exit 1
    fi
    if [ -z "${FUSE_SEC_KEY_DERIVATION_KEY}" ]; then
        echo >&2 "ERROR: --fuse-sec-key-derivation-key must be set when --create-sec-elf is enabled.  Aborting."
        exit 1
    fi
fi

if [ "${SIGNING_KEY_INDEX}" -ge "${ROOT_CERT_TOTALNUM}" ]; then
        echo >&2 "ERROR: --signing-key-index(${SIGNING_KEY_INDEX}) cannot be equal or greater to --root-cert-totalnum(${ROOT_CERT_TOTALNUM}).  Aborting."
        exit 1
fi

log "Check for ${OUT_DIR} directory"
if [ ! -d "${OUT_DIR}" ]; then
    log "> Creating ${OUT_DIR} directory"
    mkdir ${OUT_DIR}
else
    log "> Found ${OUT_DIR} directory"
fi

log "Checking for existing files in: ${OUT_DIR}"
FILES_FOUND=0
ls ${OUT_DIR}/* >/dev/null 2>&1 && FILES_FOUND=1
if [ "${FILES_FOUND}" -eq 1 ]; then
    if [ "${FORCE}" -eq 1 ]; then
        log "> Force flag enabled: overwriting existing images!"
    else
        echo >&2 "ERROR: Existing files found.  Use --force to bypass this check.  Aborting."
        exit 1
    fi
else
    log "> No files found in ${OUT_DIR}.  Proceeding."
fi

if [ ! -f "${KEYS_PATH}/${KEYS_ROOTS_HASH}" ]; then
    echo >&2 "ERROR: Cannot find roots hash file: ${KEYS_PATH}/${KEYS_ROOTS_HASH}.  Aborting."
    exit 1
fi
log "Reading the sha384 hash of the root certificate(s)."
ROOT_CERT_HASH="0x$(cat ${KEYS_PATH}/${KEYS_ROOTS_HASH} | cut -d' ' -f2)"
log "> Done"

# Define a newline
newline=$'\n'

# Get list of valid image IDs from the security profile
log "Creating a list of valid IMAGE-IDs"
OIFS="${IFS}"
IFS=${newline}
VALID_IMAGE_ID=""
SKIP_FIRST=0
for line in $(${SECTOOL} secure-image --available-image-ids --security-profile ${SECURITY_PROFILE})
do
    if [ "${SKIP_FIRST}" -eq 0 ]; then
        SKIP_FIRST=1
        continue
    fi
    NEW_ID=$(echo "${line}" | cut -c4-)
    debug_log "> Adding: ${NEW_ID}"
    VALID_IMAGE_ID+="${NEW_ID}"
    VALID_IMAGE_ID+=$'\n'
done
IFS="${OIFS}"
log "> Done"

IMAGE_ID_MAPPING="\
aop.mbn AOP${newline}\
cpucp.elf CPUCP${newline}\
devcfg.mbn TZ-DEVCFG${newline}\
hypvm.mbn QHEE${newline}\
imagefv.elf UEFIFV${newline}\
multi_image.mbn OEM-MISC${newline}\
prog_firehose_ddr.elf DEVICE-PROGRAMMER${newline}\
prog_firehose_lite.elf DEVICE-PROGRAMMER${newline}\
qupv3fw.elf QUPV3${newline}\
sec.elf SEC-ELF${newline}\
shrm.elf SHRM${newline}\
tz.mbn TZ${newline}\
uefi.elf UEFI${newline}\
uefi_sec.mbn TZ-APP-OEM${newline}\
xbl_config.elf XBL-CONFIG${newline}\
xbl_config_gunyah.elf XBL-CONFIG${newline}\
xbl_config_kvm.elf XBL-CONFIG${newline}\
xbl.elf XBL${newline}\
XblRamdump.elf XBL-RAM-DUMP${newline}\
"

# Create a list of root certificates
ROOT_CERT_LIST=""
key=0
# Loop through ROOT_CERT_TOTALNUM
while [ "${key}" -lt ${ROOT_CERT_TOTALNUM} ]
do
    KEY_FILENAME=$(echo "${KEYS_PATH}/${KEYS_ROOT_CERT}" | sed "s/###/${key}/g")
    if [ ! -f "${KEY_FILENAME}" ]; then
        echo >&2 "ERROR: Cannot find root certificate: ${KEY_FILENAME}.  Aborting."
        exit 1
    fi
    ROOT_CERT_LIST+=" ${KEY_FILENAME}"
    # increment key counter
    key=$((key + 1))
done

KEYS_CA_KEY_FILENAME=$(echo "${KEYS_PATH}/${KEYS_CA_KEY}" | sed "s/###/${SIGNING_KEY_INDEX}/g")
if [ ! -f "${KEYS_CA_KEY_FILENAME}" ]; then
    echo >&2 "ERROR: Cannot find CA key: ${KEYS_CA_KEY_FILENAME}.  Aborting."
    exit 1
fi

KEYS_CA_CERT_FILENAME=$(echo "${KEYS_PATH}/${KEYS_CA_CERT}" | sed "s/###/${SIGNING_KEY_INDEX}/g")
if [ ! -f "${KEYS_CA_CERT_FILENAME}" ]; then
    echo >&2 "ERROR: Cannot find CA certificate: ${KEYS_CA_CERT_FILENAME}.  Aborting."
    exit 1
fi

# Signing data for more than 1 root key
ROOT_CERT_INDEX=""
if [ "${ROOT_CERT_TOTALNUM}" -gt 1 ]; then
    ROOT_CERT_INDEX="--root-certificate-index ${SIGNING_KEY_INDEX}"
fi

# Get a list of *.elf and *.mbn files
for file in $(ls -1 *.elf *.mbn)
do
    debug_log "Found ${file}"

    # Lookup the IMAGE-ID from mapping
    IMAGE_ID=$(echo -e "${IMAGE_ID_MAPPING}" | grep "${file}" | cut -d' ' -f2)
    debug_log "> IMAGE_ID mapping: ${IMAGE_ID}"
    if [ -z "${IMAGE_ID}" ] || [ "${IMAGE_ID}" == "UNKNOWN" ]; then
        echo >&2 "ERROR: Unable to find IMAGE-ID mapping for ${file}.  Aborting."
        exit 1
    fi
    debug_log "> IMAGE_ID: ${IMAGE_ID}"

    if [ "${IMAGE_ID}" == "SKIP" ]; then
        log "Skip signing of ${file}"
        cp ${file} ${OUT_DIR}
        continue
    fi

    # Check to make sure the IMAGE_ID is valid for the supplied security-profile
    if echo "${VALID_IMAGE_ID}" | grep "${IMAGE_ID}" >/dev/null 2>&1; then
        debug_log "> ${IMAGE_ID} is a valid IMAGE_ID"
    else
        echo >&2 "ERROR: IMAGE_ID(${IMAGE_ID}) is not valid for this security-profile(${SECURITY_PROFILE}).  Aborting."
        exit 1
    fi

    log "Signing ${file}"
    ${SECTOOL} secure-image \
        --sign ${file} --image-id=${IMAGE_ID} \
        --security-profile ${SECURITY_PROFILE} \
        --anti-rollback-version=${ANTI_ROLLBACK_VERSION} \
        --signing-mode LOCAL \
        ${ROOT_CERT_INDEX} \
        --root-certificate ${ROOT_CERT_LIST} \
        --ca-certificate=${KEYS_CA_CERT_FILENAME} --ca-key=${KEYS_CA_KEY_FILENAME} \
        --outfile ${OUT_DIR}/${file}

    log "> Verifying root hash of ${OUT_DIR}/${file}"
    ${SECTOOL} secure-image --verify-root ${ROOT_CERT_HASH} ${OUT_DIR}/${file}
    if [ $? -ne 0 ]; then
        echo >&2 "ERROR: Root hash of ${OUT_DIR}/${file} failed verification.  Aborting."
        exit 1
    fi
    log "> Verified."
done

log "Image signing complete."

# Create basic_sec.elf and sec.elf
# TOOD: Handle more than 1 root key
if [ "${CREATE_SEC_ELF}" -eq 1 ]; then
    FUSE_ROOT_TOTAL_NUM=""
    ROOT_CERT_COUNT_INDEX=""
    if [ "${ROOT_CERT_TOTALNUM}" -gt 1 ]; then
        root_total_num=$((ROOT_CERT_TOTALNUM - 1))
        FUSE_ROOT_TOTAL_NUM="--fuse-root-cert-total-num 0x${root_total_num}"
        ROOT_CERT_COUNT_INDEX="--root-certificate-index ${SIGNING_KEY_INDEX}"
    fi

    log "Creating basic secure boot file (basic_sec.elf)."

    ${SECTOOL} fuse-blower \
        --security-profile ${SECURITY_PROFILE} \
        --fuse-pk-hash-0=${ROOT_CERT_HASH} \
        --fuse-oem-secure-boot1-pk-hash-in-fuse --fuse-oem-secure-boot1-auth-en \
        --fuse-oem-secure-boot2-pk-hash-in-fuse --fuse-oem-secure-boot2-auth-en \
        --fuse-oem-secure-boot3-pk-hash-in-fuse --fuse-oem-secure-boot3-auth-en \
        --fuse-oem-hw-id=${FUSE_OEM_HW_ID} --fuse-oem-product-id=${FUSE_OEM_PRODUCT_ID} \
        ${FUSE_ROOT_TOTAL_NUM} \
        --generate --sign --signing-mode=LOCAL \
        ${ROOT_CERT_COUNT_INDEX} \
        --root-certificate ${ROOT_CERT_LIST} \
        --ca-certificate ${KEYS_CA_CERT_FILENAME} --ca-key ${KEYS_CA_KEY_FILENAME} \
        --outfile ${OUT_DIR}/basic_sec.elf

    log "> Verifying root hash of ${OUT_DIR}/basic_sec.elf"
    ${SECTOOL} fuse-blower --verify-root ${ROOT_CERT_HASH} ${OUT_DIR}/basic_sec.elf
    if [ $? -ne 0 ]; then
        echo >&2 "ERROR: Root hash of ${OUT_DIR}/basic_sec.elf failed verification.  Aborting."
        exit 1
    fi
    log "> Verified."

    log "Creating complete secure boot file (sec.elf)."

    ${SECTOOL} fuse-blower \
        --security-profile ${SECURITY_PROFILE} \
        --fuse-pk-hash-0=${ROOT_CERT_HASH} \
        --fuse-oem-secure-boot1-pk-hash-in-fuse --fuse-oem-secure-boot1-auth-en \
        --fuse-oem-secure-boot2-pk-hash-in-fuse --fuse-oem-secure-boot2-auth-en \
        --fuse-oem-secure-boot3-pk-hash-in-fuse --fuse-oem-secure-boot3-auth-en \
        --fuse-oem-secure-boot-fec-enable --fuse-wdog-en \
        --fuse-shared-qsee-spiden-disable --fuse-shared-qsee-spniden-disable \
        --fuse-shared-mss-dbgen-disable --fuse-shared-mss-niden-disable \
        --fuse-shared-cp-dbgen-disable --fuse-shared-cp-niden-disable \
        --fuse-shared-ns-dbgen-disable --fuse-shared-ns-niden-disable \
        --fuse-apps-dbgen-disable --fuse-apps-niden-disable \
        --fuse-shared-misc-debug-disable \
        --fuse-eku-enforcement-en \
        --fuse-anti-rollback-feature-en=0xF \
        --fuse-sec-key-derivation-key=${FUSE_SEC_KEY_DERIVATION_KEY} \
        --fuse-read-permissions-write-disable \
        --fuse-oem-configuration-write-disable \
        --fuse-secondary-key-derivation-key-read-disable \
        --fuse-public-key-hash-0-write-disable \
        --fuse-oem-secure-boot-write-disable \
        --fuse-secondary-key-derivation-key-write-disable --fuse-secondary-key-derivation-key-fec-enable \
        --fuse-fec-enables-write-disable \
        --fuse-oem-hw-id=${FUSE_OEM_HW_ID} --fuse-oem-product-id=${FUSE_OEM_PRODUCT_ID} \
        ${FUSE_ROOT_TOTAL_NUM} \
        --generate --sign --signing-mode=LOCAL \
        ${ROOT_CERT_COUNT_INDEX} \
        --root-certificate ${ROOT_CERT_LIST} \
        --ca-certificate ${KEYS_CA_CERT_FILENAME} --ca-key ${KEYS_CA_KEY_FILENAME} \
        --outfile ${OUT_DIR}/sec.elf

    log "> Verifying root hash of ${OUT_DIR}/sec.elf"
    ${SECTOOL} fuse-blower --verify-root ${ROOT_CERT_HASH} ${OUT_DIR}/sec.elf
    if [ $? -ne 0 ]; then
        echo >&2 "ERROR: Root hash of ${OUT_DIR}/sec.elf failed verification.  Aborting."
        exit 1
    fi
    log "> Verified."
fi

if [ ! -z "${PACKAGE_FILENAME}" ]; then
    log "Copying non- *.elf and *.mbn files to ${OUT_DIR}"
    find . -maxdepth 1 -type f -not -iname "*.elf" -not -iname "*.mbn" -exec cp "{}" "${OUT_DIR}/{}" ';'
    log "> Done."

    log "Creating zip package of ${OUT_DIR}"
    zip -r ${PACKAGE_FILENAME} ${OUT_DIR}
    log "> Done."
fi
