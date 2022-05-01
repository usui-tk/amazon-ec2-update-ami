#!/bin/bash
#set -eux
DOCUMENT_BUILD_VERSION="1.0.2"
PUBKEY_FILE="inspector.gpg"
INSTALLER_FILE="install"
SIG_FILE="install.sig"
function make_temp_dir() {
local stamp
stamp=$(date +%Y%m%d%H%M%S)
SECURE_TMP_DIR=${TMPDIR:-/tmp}/$stamp-$(awk 'BEGIN { srand (); print rand() }')-$$
mkdir -m 700 -- "$SECURE_TMP_DIR" 2>/dev/null
if [ $? -eq 0 ]; then
 return 0
else
  echo "Could not create temporary directory"
  return 1
fi
}
declare SECURE_TMP_DIR
if ! make_temp_dir; then
  exit 1
fi
trap "rm -rf ${SECURE_TMP_DIR}" EXIT
PUBKEY_PATH="${SECURE_TMP_DIR}/${PUBKEY_FILE}"
INSTALLER_PATH="${SECURE_TMP_DIR}/${INSTALLER_FILE}"
SIG_PATH="${SECURE_TMP_DIR}/${SIG_FILE}"
if hash curl 2>/dev/null
then
  DOWNLOAD_CMD="curl -s --fail --retry 5 --max-time 30"
  CONSOLE_ARG=""
  TO_FILE_ARG=" -o "
  PUT_METHOD_ARG=" -X PUT "
  HEADER_ARG=" --head "
else
  DOWNLOAD_CMD="wget --quiet --tries=5 --timeout=30 "
  CONSOLE_ARG=" -qO- "
  TO_FILE_ARG=" -O "
  PUT_METHOD_ARG=" --method=PUT "
  HEADER_ARG=" -S --spider "
fi
IMDSV2_TOKEN=$( ${DOWNLOAD_CMD} ${CONSOLE_ARG} ${PUT_METHOD_ARG} --header "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token)
IMDSV2_TOKEN_HEADER=""
if [[ -n "${IMDSV2_TOKEN}" ]]; then
    IMDSV2_TOKEN_HEADER=" --header X-aws-ec2-metadata-token:${IMDSV2_TOKEN} "
fi
METADATA_AZ=$( ${DOWNLOAD_CMD} ${CONSOLE_ARG} ${IMDSV2_TOKEN_HEADER} http://169.254.169.254/latest/meta-data/placement/availability-zone)
METADATA_REGION=$( echo $METADATA_AZ | sed -e "s/[a-z]*$//" )
if [[ -n "${METADATA_REGION}" ]]; then
  REGION=${METADATA_REGION}
else
  echo "No region information was obtained."
  exit 2
fi
AGENT_INVENTORY_FILE="AWS_AGENT_INVENTORY"
BASE_URL="https://s3.dualstack.${REGION}.amazonaws.com/aws-agent.${REGION}/linux/latest"
PUBKEY_FILE_URL="${BASE_URL}/${PUBKEY_FILE}"
INSTALLER_FILE_URL="${BASE_URL}/${INSTALLER_FILE}"
SIG_FILE_URL="${BASE_URL}/${SIG_FILE}"
AGENT_METRICS_URL="${BASE_URL}/${AGENT_INVENTORY_FILE}?x-installer-version=${DOCUMENT_BUILD_VERSION}&x-installer-type=ssm-installer&x-op={{Operation}}"
function handle_status() {
  local result_param="nil"
  local result="nil"
  if [[ $# -eq 0 ]]; then
    echo "Error while handling status function. At least one argument should be passed."
      exit 129
  else
    if [[ $# > 1 ]]; then
      result_param=$2
    fi
    result=$1
  fi
  #start publishing metrics
  ${DOWNLOAD_CMD} ${HEADER_ARG} "${AGENT_METRICS_URL}&x-result=${result}&x-result-param=${result_param}"
  echo "Script exited with status code ${result} ${result_param}"
  if [[ "${result}" = "SUCCESS" ]]; then
    exit 0
  else
    exit 1
  fi
}
#get the public key
${DOWNLOAD_CMD} ${TO_FILE_ARG} "${PUBKEY_PATH}" ${PUBKEY_FILE_URL}
if [[ $? != 0 ]]; then
  echo "Failed to download public key from ${PUBKEY_FILE_URL}"
  handle_status "FILE_DOWNLOAD_ERROR" "${PUBKEY_PATH}"
fi
#get the installer
${DOWNLOAD_CMD} ${TO_FILE_ARG} "${INSTALLER_PATH}" ${INSTALLER_FILE_URL}
if [[ $? != 0 ]]; then
  echo "Failed to download installer from ${INSTALLER_FILE_URL}"
  handle_status "FILE_DOWNLOAD_ERROR" "${INSTALLER_PATH}"
fi
#get the signature
${DOWNLOAD_CMD} ${TO_FILE_ARG} "${SIG_PATH}" ${SIG_FILE_URL}
if [[ $? != 0 ]]; then
  echo "Failed to download installer signature from ${SIG_FILE_URL}"
  handle_status "FILE_DOWNLOAD_ERROR" "${SIG_PATH}"
fi
gpg_results=$( gpg -q --no-default-keyring --keyring "${PUBKEY_PATH}" --verify "${SIG_PATH}" "${INSTALLER_PATH}" 2>&1 )
if [[ $? -eq 0 ]]; then
  echo "Validated " "${INSTALLER_PATH}" "signature with: $(echo "${gpg_results}" | grep -i fingerprint)"
else
  echo "Error validating signature of " "${INSTALLER_PATH}" ", terminating.  Please contact AWS Support."
  echo ${gpg_results}
  handle_status "SIGNATURE_MISMATCH" "${INSTALLER_PATH}"
fi
bash ${INSTALLER_PATH}
