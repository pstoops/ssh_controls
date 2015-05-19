#!/bin/env ksh
#******************************************************************************
# @(#) manage_ssh.sh
#******************************************************************************
# @(#) Copyright (C) 2014 by KUDOS BVBA <info@kudos.be>.  All rights reserved.
#
# This program is a free software; you can redistribute it and/or modify
# it under the same terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details
#******************************************************************************
#
# DOCUMENTATION (MAIN)
# -----------------------------------------------------------------------------
# @(#) MAIN: manage_ssh.sh
# DOES: performs basic functions for SSH controls: update SSH keys locally or
#       remote, create SSH key fingerprints or distribute the SSH controls files
# EXPECTS: (see --help for more options)
# REQUIRES: check_config(), check_logging(), check_params(), check_setup(),
#           check_syntax(), count_fields(), die(), display_usage(), 
#           distribute2host(), do_cleanup(), fix2host(), get_linux_version(), 
#           log(), resolve_host(), sftp_file(), update2host(), 
#           update_fingerprints(), warn()
#           For other pre-requisites see the documentation in display_usage()
#
# @(#) HISTORY:
# @(#) 2014-12-16: initial version (VRF 1.0.0) [Patrick Van der Veken]
# @(#) 2014-12-20: updated SELinux contexts (VRF 1.0.1) [Patrick Van der Veken]
# @(#) 2015-01-05: added backup feature, see --backup (VRF 1.1.0) [Patrick Van der Veken]
# @(#) 2015-01-19: updated display_usage() (VRF 1.1.1) [Patrick Van der Veken]
# @(#) 2015-02-03: use 'sudo -n' (VRF 1.1.2) [Patrick Van der Veken]
# @(#) 2015-04-10: fix in --fix-local routine (VRF 1.1.3) [Patrick Van der Veken]
# @(#) 2015-05-16: added SSH_OWNER_GROUP (VRF 1.1.4) [Patrick Van der Veken]
# -----------------------------------------------------------------------------
# DO NOT CHANGE THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING!
#******************************************************************************

#******************************************************************************
# DATA structures
#******************************************************************************

# ------------------------- CONFIGURATION starts here -------------------------
# define the V.R.F (version/release/fix)
MY_VRF="1.1.4"
# name of the user account performing the SSH controls copies
# (leave blank for current user)
SSH_TRANSFER_USER=""
# name of the OS group that should own the SSH controls files
SSH_OWNER_GROUP="sshadmin"
# extra arguments/options for the SFTP command
SFTP_ARGS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -b - "
# extra arguments/options for the SSH command
SSH_ARGS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -n"
# location of the local SSH controls directory
LOCAL_DIR="/etc/ssh_master"
# location of the remote SSH controls directory
REMOTE_DIR="/etc/ssh_controls/holding"
# name of the user account performing the SSH controls update
# (leave blank for current user but user should have remote sudo root privs)
SSH_UPDATE_USER=""
# options to pass to manage_ssh.sh when executing a key update
SSH_UPDATE_OPTS="--verbose --remove"
# maximum number of background process to spawn (~maxuprc, ~nstrpty etc)
MAX_BACKGROUND_PROCS=30
# location of the backup directory (for configuration & key files)
BACKUP_DIR="${LOCAL_DIR}/backup"
# location of log directory (default), see --log-dir)
LOG_DIR="/var/log"
# location of temporary working storage
TMP_DIR="/var/tmp"
# ------------------------- CONFIGURATION ends here ---------------------------
# miscelleaneous
PATH=${PATH}:/usr/bin:/usr/local/bin
SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(dirname $0)
OS_NAME="$(uname)"
KEYS_FILE=""
KEYS_DIR=""
TARGETS_FILE=""
FIX_CREATE=0
KEY_COUNT=0
KEY_1024_COUNT=0
KEY_2048_COUNT=0
KEY_4096_COUNT=0
KEY_OTHER_COUNT=0
TMP_FILE="${TMP_DIR}/.${SCRIPT_NAME}.$$"
# command-line parameters
ARG_ACTION=0            # default is nothing
ARG_FIX_DIR=""          # location of SSH controls directory
ARG_LOG_DIR=""          # location of the log directory (~root etc)
ARG_LOCAL_DIR=""        # location of the local SSH control files
ARG_REMOTE_DIR=""       # location of the remote SSH control files
ARG_TARGETS=""          # list of remote targets
ARG_LOG=1               # logging is on by default
ARG_VERBOSE=1           # STDOUT is on by default
ARG_DEBUG=0             # debug is off by default


#******************************************************************************
# FUNCTION routines
#******************************************************************************

# -----------------------------------------------------------------------------
function check_config
{
# SSH_TRANSFER_USER
if [[ -z "${SSH_TRANSFER_USER}" ]]
then
    SSH_TRANSFER_USER="${LOGNAME}"
    if [[ -z "${SSH_TRANSFER_USER}" ]]
    then
        print -u2 "ERROR: unable to set a value for SSH_TRANSFER_USER in $0"
        exit 1
    fi
fi
# LOCAL_DIR
if [[ -z "${LOCAL_DIR}" ]]
then
    print -u2 "ERROR: you must define a value for the LOCAL_DIR setting in $0"
    exit 1
fi
# REMOTE_DIR
if [[ -z "${REMOTE_DIR}" ]]
then
    print -u2 "ERROR: you must define a value for the REMOTE_DIR setting in $0"
    exit 1
fi
# SSH_UPDATE_USER
if [[ -z "${SSH_UPDATE_USER}" ]]
then
    SSH_UPDATE_USER="${LOGNAME}"
    if [[ -z "${SSH_UPDATE_USER}" ]]
    then
        print -u2 "ERROR: unable to set a value for SSH_UPDATE_USER in $0"
        exit 1
    fi
fi
# MAX_BACKGROUND_PROCS
if [[ -z "${MAX_BACKGROUND_PROCS}" ]]
then
    print -u2 "ERROR: you must define a value for the MAX_BACKGROUND_PROCS setting in $0"
    exit 1
fi
# BACKUP_DIR
if [[ -z "${BACKUP_DIR}" ]]
then
    print -u2 "ERROR: you must define a value for the BACKUP_DIR setting in $0"
    exit 1
fi

return 0
}

# -----------------------------------------------------------------------------
function check_logging
{
if (( ARG_LOG ))
then
    if [[ ! -d "${LOG_DIR}" ]]
    then
        if [[ ! -w "${LOG_DIR}" ]]
        then
            # switch off logging intelligently when needed for permission problems 
            # since this script may run with root/non-root actions
            print -u2 "ERROR: unable to write to the log directory at ${LOG_DIR}, disabling logging"
            ARG_LOG=0  
        fi
    else
        if [[ ! -w "${LOG_FILE}" ]]
        then    
            # switch off logging intelligently when needed for permission problems 
            # since this script may run with root/non-root actions
            print -u2 "ERROR: unable to write to the log file at ${LOG_FILE}, disabling logging"
            ARG_LOG=0
        fi
    fi
fi

return 0
}

# -----------------------------------------------------------------------------
function check_params
{
# -- ALL
if (( ARG_ACTION < 1 || ARG_ACTION > 9 ))
then
    display_usage
    exit 0
fi
# --fix-local + --fix-dir
if (( ARG_ACTION == 5 ))
then
    if [[ -z "${ARG_FIX_DIR}" ]]
    then
        print -u2 "ERROR: you must specify a value for parameter '--fix-dir"
        exit 1
    else
        FIX_DIR="${ARG_FIX_DIR}"
    fi    
fi
# --local-dir
if [[ -n "${ARG_LOCAL_DIR}" ]]
then
    if [ \( ! -d "${ARG_LOCAL_DIR}" \) -o \( ! -r "${ARG_LOCAL_DIR}" \) ]
    then
        print -u2 "ERROR: unable to read directory ${ARG_LOCAL_DIR}"
        exit 1
    else
        LOCAL_DIR="${ARG_LOCAL_DIR}"
    fi    
fi
# --log-dir
[[ -z "${ARG_LOG_DIR}" ]] || LOG_DIR="${ARG_LOG_DIR}"
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"
# --remote-dir
if (( ARG_ACTION == 1 || ARG_ACTION == 2 ))
then
    if [[ -n "${ARG_REMOTE_DIR}" ]]
    then
        REMOTE_DIR="${ARG_REMOTE_DIR}"
    fi
fi
# --targets
if [[ -n "${ARG_TARGETS}" ]]
then
    > ${TMP_FILE}
    # write comma-separated target list to the temporary file
    print "${ARG_TARGETS}" | tr -s ',' '\n' | while read TARGET_HOST
    do
        print ${TARGET_HOST} >>${TMP_FILE}
    done
fi
# --update + --fix-local
if (( ARG_ACTION == 4 || ARG_ACTION == 5 ))
then
    if [[ -n "${TARGETS}" ]]
    then
        print -u2 "ERROR: you cannot specify '--targets' in this context!"
        exit 1
    fi
fi

return 0
}

# -----------------------------------------------------------------------------
function check_root_user
{
(IFS='()'; set -- $(id); print $2) | read UID
if [[ "${UID}" = "root" ]]
then
    return 0
else
    return 1
fi
}

# -----------------------------------------------------------------------------
function check_setup
{
# use added fall back for LOCAL_DIR (the default script directory)
[[ -d "${LOCAL_DIR}" ]] || LOCAL_DIR="${SCRIPT_DIR}"

# check for basic SSH control files: access/alias
for FILE in "${LOCAL_DIR}/access" "${LOCAL_DIR}/alias"
do
    if [[ ! -r "${FILE}" ]]
    then
        print -u2 "ERROR: cannot read file ${FILE}"
        exit 1    
    fi
done
# check for basic SSH control file(s): targets, /var/tmp/targets.$USER (or $TMP_FILE)
if (( ARG_ACTION == 1 || ARG_ACTION == 2 || ARG_ACTION == 6 ))
then
    if [[ -z "${ARG_TARGETS}" ]]
    then
        TARGETS_FILE="${LOCAL_DIR}/targets"
        if [ \( ! -r "${TARGETS_FILE}" \) -a \( ! -r "/var/tmp/targets.${USER}" \) ]
        then
            print -u2 "ERROR: cannot read file ${TARGETS_FILE} nor /var/tmp/targets.${USER}"
            exit 1    
        fi
        # override default targets file
        [[ -r "/var/tmp/targets.${USER}" ]] && TARGETS_FILE="/var/tmp/targets.${USER}"
    else
        TARGETS_FILE=${TMP_FILE}    
    fi
fi
# check for basic SSH control file(s): keys, keys.d/*
if [[ -d "${LOCAL_DIR}/keys.d" && -f "${LOCAL_DIR}/keys" ]]
then
    print -u2 "WARN: found both a 'keys' file (${LOCAL_DIR}/keys) and a 'keys.d' directory (${LOCAL_DIR}/keys.d). Ignoring the 'keys' file"
fi
if [[ -d "${LOCAL_DIR}/keys.d" ]]
then
    KEYS_DIR="${LOCAL_DIR}/keys.d"
    if [[ ! -r "${KEYS_DIR}" ]]
    then
        print -u2 "ERROR: unable to read directory ${KEYS_DIR}"
        exit 1    
    fi  
elif [[ -f "${LOCAL_DIR}/keys" ]]
then
    KEYS_FILE="${LOCAL_DIR}/keys"
    if [[ ! -r "${KEYS_FILE}" ]]
    then
        print -u2 "ERROR: cannot read file ${KEYS_FILE}"
        exit 1    
    fi
else
    print -u2 "ERROR: could not found any public keys in ${LOCAL_DIR}!"
    exit 1  
fi
# check for SSH control scripts & configurations (not .local)
if (( ARG_ACTION == 1 || ARG_ACTION == 2 || ARG_ACTION == 4 ))
then
    for FILE in "${LOCAL_DIR}/update_ssh.pl" \
                "${LOCAL_DIR}/update_ssh.conf" \
                "${SCRIPT_DIR}/${SCRIPT_NAME}"
    do
        if [[ ! -r "${FILE}" ]]
        then
            print -u2 "ERROR: cannot read file ${FILE}"
            exit 1    
        fi
    done    
fi


return 0
}

# -----------------------------------------------------------------------------
function check_syntax
{
# access should have 3 fields
cat "${LOCAL_DIR}/access" | grep -v -E -e '^#|^$' | while read ACCESS_LINE
do
    ACCESS_FIELDS=$(count_fields "${ACCESS_LINE}" ":")
    (( ACCESS_FIELDS != 3 )) && \die "line '${ACCESS_LINE}' in access file has missing or too many field(s) (should be 3)"
done

# alias should have 2 fields
cat "${LOCAL_DIR}/alias" | grep -v -E -e '^#|^$' | while read ALIAS_LINE
do
    ALIAS_FIELDS=$(count_fields "${ALIAS_LINE}" ":")
    (( ALIAS_FIELDS != 2 )) && die "line '${ALIAS_LINE}' in alias file has missing or too many field(s) (should be 2)"
done

# key files should have 3 fields
ls -1 ${LOCAL_DIR}/keys.d/* ${LOCAL_DIR}/keys 2>/dev/null | while read KEY_FILE
do
    cat ${KEY_FILE} 2>/dev/null | grep -v -E -e '^#|^$' |\
    while read KEY_LINE
    do
        KEY_FIELDS=$(count_fields "${KEY_LINE}" ",")
        (( KEY_FIELDS != 3 )) && die "line '${KEY_LINE}' in a keys file has missing or too many field(s) (should be 3)"
    done
done

return 0
}

# -----------------------------------------------------------------------------
function count_fields
{
CHECK_LINE="$1"
CHECK_DELIM="$2"

NUM_FIELDS=$(print "${CHECK_LINE}" | awk -F "${CHECK_DELIM}" '{ print NF }')

print $NUM_FIELDS

return ${NUM_FIELDS}
}

# -----------------------------------------------------------------------------
function die
{
NOW="$(date '+%d-%h-%Y %H:%M:%S')"

if [[ -n "$1" ]]
then
    if (( ARG_LOG ))
    then
        print - "$*" | while read LOG_LINE
        do
            # filter leading 'ERROR:'
            LOG_LINE="${LOG_LINE#ERROR: *}"
            print "${NOW}: ERROR: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    print - "$*" | while read LOG_LINE
    do
        # filter leading 'ERROR:'
        LOG_LINE="${LOG_LINE#ERROR: *}"
        print -u2 "ERROR:" "${LOG_LINE}"
    done
fi

# finish up work
do_cleanup

exit 1
}

# -----------------------------------------------------------------------------
function display_usage
{
cat << EOT

**** ${SCRIPT_NAME} ****
**** (c) KUDOS BVBA - Patrick Van der Veken ****

Performs basic functions for SSH controls: update SSH keys locally or
remote, create SSH key fingerprints or copy/distribute the SSH controls files

Syntax: ${SCRIPT_DIR}/${SCRIPT_NAME} [--help] | (--backup | --check-syntax | --preview-global | --make-finger | --update ) | 
            (--apply [--remote-dir=<remote_directory>] [--targets=<host1>,<host2>,...]) |
                ((--copy|--distribute) [--remote-dir=<remote_directory> [--targets=<host1>,<host2>,...]]) |
                    ([--fix-local --fix-dir=<repository_dir> [--create-dir]] | [--fix-remote [--create-dir] [--targets=<host1>,<host2>,...]])
                         [--local-dir=<local_directory>] [--no-log] [--log-dir=<log_directory>] [--debug]
 
Parameters:

--apply|-a          : apply SSH controls remotely (~targets)
--backup|-b         : create a backup of the SSH controls repository (SSH master)
--create-dir        : also create missing directories when fixing the SSH controls
                      repository (see also --fix-local/--fix-remote)
--check-syntax|-s   : do basic syntax checking on SSH controls configuration
                      (access, alias & keys files) 
--copy|-c           : copy SSH control files to remote host (~targets)
--debug             : print extra status messages on STDERR
--distribute|-d     : same as --copy
--fix-dir           : location of the local SSH controls client repository
--fix-local         : fix permissions on the local SSH controls repository
                      (local SSH controls repository given by --fix-dir)
--fix-remote        : fix permissions on the remote SSH controls repository
--help|-h           : this help text
--local-dir         : location of the SSH control files on the local filesystem.
                      [default: ${LOCAL_DIR}]
--log-dir           : specify a log directory location.
--no-log            : do not log any messages to the script log file.
--make-finger|-m    : create (local) key fingerprints file
--preview-global|-p : dump the global access namespace (after alias resolution)
--remote-dir        : directory where SSH control files are/should be 
                      located/copied on/to the target host
                      [default: ${REMOTE_DIR}]
--targets           : comma-separated list of target hosts to operate on. Override the 
                      hosts contained in the 'targets' configuration file.
--update|-u         : apply SSH controls locally

--version|-V        : show the script version/release/fix

Note 1: distribute and update actions are run in parallel across a maximum of
        ${MAX_BACKGROUND_PROCS} clients at the same time.

Note 2: for fix and update actions: make sure correct 'sudo' rules are setup 
        on the target systems to allow the SSH controls script to run with 
        elevated privileges.

EOT

return 0
}

# -----------------------------------------------------------------------------
# distribute SSH controls to a single host/client 
function distribute2host
{
SERVER="$1"

# convert line to hostname
SERVER=${SERVER%%;*}
resolve_host ${SERVER}
if (( $? ))
then
    warn "could not lookup host ${SERVER}, skipping"
    return 1
fi

# specify copy objects as 'filename!permissions'
# 1) config files & scripts
for FILE in "${LOCAL_DIR}/access!660" \
            "${LOCAL_DIR}/alias!660" \
            "${LOCAL_DIR}/update_ssh.pl!770" \
            "${LOCAL_DIR}/update_ssh.conf!660" \
            "${SCRIPT_DIR}/${SCRIPT_NAME}!770" 
do              
    # sftp transfer
    sftp_file ${FILE} ${SERVER}
    COPY_RC=$?
    if (( ! COPY_RC ))
    then
        log "transferred ${FILE%!*} to ${SERVER}:${REMOTE_DIR}"
    else
        warn "failed to transfer ${FILE%!*} to ${SERVER}:${REMOTE_DIR} [RC=${COPY_RC}]"
    fi
done
# 2) keys files
# are keys stored a file or a directory?
if [[ -n "${KEYS_DIR}" ]]
then
    # merge keys file(s) before copy (in a temporary location)
    TMP_WORK_DIR="${TMP_DIR}/$0.${RANDOM}"
    mkdir -p ${TMP_WORK_DIR}
    if (( $? ))
    then
        die "unable to create temporary directory ${TMP_WORK_DIR} for mangling of 'keys' file"
    fi
    TMP_MERGE_FILE="${TMP_WORK_DIR}/keys"
    log "keys are stored in a DIRECTORY, first merging all keys into ${TMP_MERGE_FILE}"
    cat ${KEYS_DIR}/* >${TMP_MERGE_FILE}
    # sftp transfer
    sftp_file "${TMP_MERGE_FILE}!440" ${SERVER}
    COPY_RC=$?
    if (( ! COPY_RC ))
    then
        log "transferred ${TMP_MERGE_FILE} to ${SERVER}:${REMOTE_DIR}"
    else
        warn "failed to transfer ${TMP_MERGE_FILE%!*} to ${SERVER}:${REMOTE_DIR} [RC=${COPY_RC}]"
    fi
    [[ -d ${TMP_WORK_DIR} ]] && rm -rf ${TMP_WORK_DIR} 2>/dev/null
else
    sftp_file "${KEYS_FILE}!440" ${SERVER}
    COPY_RC=$?
    if (( ! COPY_RC ))
    then
        log "transferred ${KEYS_FILE} to ${SERVER}:${REMOTE_DIR}"
    else
        warn "failed to transfer ${KEYS_FILE} to ${SERVER}:${REMOTE_DIR} [RC=${COPY_RC}]"
    fi
fi
# discover a keys blacklist file, also copy it across if we find one
# never use a keys blacklist file from the local config though
[[ -r ${LOCAL_DIR}/keyupdate.conf ]] && \
    BLACKLIST_FILE="$(grep -E -e '^blacklist_file' ${LOCAL_DIR}/update_ssh.conf 2>/dev/null | cut -f2 -d'=')"
if [[ -n "${BLACKLIST_FILE}" ]]
then
    if [[ -r "${BLACKLIST_FILE}" ]]
    then
        log "keys blacklist file found at ${BLACKLIST_FILE}"
        # sftp transfer
        sftp_file "${BLACKLIST_FILE}!660" ${SERVER}
        COPY_RC=$?
        if (( ! COPY_RC ))
        then
            log "transferred ${BLACKLIST_FILE} to ${SERVER}:${REMOTE_DIR}"
        else
            warn "failed to transfer ${BLACKLIST_FILE%!*} to ${SERVER}:${REMOTE_DIR} [RC=${COPY_RC}]"
        fi
    fi
fi

return 0
}

# -----------------------------------------------------------------------------
function do_cleanup
{
log "performing cleanup ..."

# remove temporary file
[[ -f ${TMP_FILE} ]] && rm -f ${TMP_FILE} >/dev/null 2>&1
[[ -f ${TMP_MERGE_FILE} ]] && rm -f ${TMP_MERGE_FILE} >/dev/null 2>&1

log "*** finish of ${SCRIPT_NAME} [${CMD_LINE}] ***"

return 0
}

# -----------------------------------------------------------------------------
# fix SSH controls on a single host/client (permissions/ownerships)
# !! requires appropriate 'sudo' rules on remote client for privilege elevation
function fix2host
{
SERVER="$1"
SERVER_DIR="$2"

# convert line to hostname
SERVER=${SERVER%%;*}
resolve_host ${SERVER}
if (( $? ))
then
    warn "could not lookup host ${SERVER}, skipping"
    return 1
fi
        
log "fixing ssh controls on ${SERVER} ..."
if [[ -z "${SSH_UPDATE_USER}" ]]
then
    # own user w/ sudo
    log "$(ssh ${SSH_ARGS} ${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --fix-local --fix-dir=${SERVER_DIR})"
elif [[ "${SSH_UPDATE_USER}" != "root" ]]
then
    # other user w/ sudo
    log "$(ssh ${SSH_ARGS} ${SSH_UPDATE_USER}@${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --fix-local --fix-dir=${SERVER_DIR})"
else
    # root user w/o sudo
    log "$(ssh ${SSH_ARGS} ${SSH_UPDATE_USER}@${SERVER} ${REMOTE_DIR}/${SCRIPT_NAME} --fix-local --fix-dir=${SERVER_DIR})"
fi
# no error checking possible here due to log(), done in called script

return 0
}

# -----------------------------------------------------------------------------
function get_linux_version
{
LSB_VERSION=$(lsb_release -rs 2>/dev/null | cut -f1 -d'.')

if [[ -z "${LSB_VERSION}" ]]
then
    RELEASE_STRING=$(/bin/grep -i 'release' /etc/redhat-release 2>/dev/null)
    
    case "${RELEASE_STRING}" in
        *release\ 5*)
            RHEL_VERSION=5
            ;;
        *release\ 6*)
            RHEL_VERSION=6
            ;;
        *release\ 7*)
            RHEL_VERSION=7
            ;;
        *)
            RHEL_VERSION=""
            ;;
    esac
    print "${RHEL_VERSION}"
else
    print "${LSB_VERSION}"
fi
}

# -----------------------------------------------------------------------------
function log
{
NOW="$(date '+%d-%h-%Y %H:%M:%S')"

if [[ -n "$1" ]]
then
    if (( ARG_LOG ))
    then
        print - "$*" | while read LOG_LINE
        do
            # filter leading 'INFO:'
            LOG_LINE="${LOG_LINE#INFO: *}"
            print "${NOW}: INFO: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    if (( ARG_VERBOSE ))
    then
        print - "$*" | while read LOG_LINE
        do
            # filter leading 'INFO:'
            LOG_LINE="${LOG_LINE#INFO: *}"
            print "INFO:" "${LOG_LINE}"
        done
    fi
fi

return 0
}

# -----------------------------------------------------------------------------
# resolve a host (check)
function resolve_host
{
LOOKUP_HOST="$1"

nslookup $1 2>/dev/null | grep -q -E -e 'Address:.*([0-9]{1,3}[\.]){3}[0-9]{1,3}'

return $?
}

# -----------------------------------------------------------------------------
# transfer a file using sftp
function sftp_file 
{
TRANSFER_FILE="$1"
TRANSFER_HOST="$2"

# find the local directory & permission bits
TRANSFER_DIR="${TRANSFER_FILE%/*}"
TRANSFER_PERMS="${TRANSFER_FILE##*!}"
# cut out the permission bits and the directory path
TRANSFER_FILE="${TRANSFER_FILE%!*}"
SOURCE_FILE="${TRANSFER_FILE##*/}"
OLD_PWD=$(pwd) && cd ${TRANSFER_DIR}

# transfer, chmod the file to/on the target server (keep STDERR)
# chmod is not possible in the used security model as files should be 
# owned by root, so must be disabled. This requires a fix operation right
# after the very first initial SSH controls distribution:
# ./manage_ssh.sh --fix-local --fix-dir=/etc/ssh_controls
sftp ${SFTP_ARGS} ${SSH_TRANSFER_USER}@${TRANSFER_HOST} >/dev/null <<EOT
cd ${REMOTE_DIR}
put ${SOURCE_FILE}
#chmod ${TRANSFER_PERMS} ${SOURCE_FILE}
EOT
SFTP_RC=$?

cd ${OLD_PWD}

return ${SFTP_RC}
}

# -----------------------------------------------------------------------------
# update SSH controls on a single host/client 
# !! requires appropriate 'sudo' rules on remote client for privilege elevation
function update2host
{
SERVER="$1"

# convert line to hostname
SERVER=${SERVER%%;*}
resolve_host ${SERVER}
if (( $? ))
then
    warn "could not lookup host ${SERVER}, skipping"
    return 1
fi
        
log "setting ssh controls on ${SERVER} ..."
if [[ -z "${SSH_UPDATE_USER}" ]]
then
    # own user w/ sudo
    log "$(ssh ${SSH_ARGS} ${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --update)"
elif [[ "${SSH_UPDATE_USER}" != "root" ]]
then
    # other user w/ sudo
    log "$(ssh ${SSH_ARGS} ${SSH_UPDATE_USER}@${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --update)"
else
    # root user w/o sudo
    log "$(ssh ${SSH_ARGS} ${SSH_UPDATE_USER}@${SERVER} ${REMOTE_DIR}/${SCRIPT_NAME} --update)"
fi
# no error checking possible here due to log(), done in called script

return 0
}

# -----------------------------------------------------------------------------
# update the 'fingerprints' file (must exist beforehand)
function update_fingerprints
{
FINGER_LINE="$1"

# check for empty line
[[ -z "${FINGER_LINE}" ]] && log "skipping empty line in keys file" && return 0

# line should have 3 fields
FINGER_FIELDS=$(count_fields "${FINGER_LINE}" ",")
(( FINGER_FIELDS != 3 )) && \die "line '${FINGER_LINE}' has missing or too many field(s) (should be 3))"

# create fingerprint
FINGER_USER="$(print ${FINGER_LINE} | awk -F, '{print $1}')"
print "${FINGER_LINE}" | awk -F, '{print $2," ",$3}' > ${TMP_FILE}
# check if fingerprint is valid
FINGERPRINT="$(ssh-keygen -l -f ${TMP_FILE} 2>&1)"
FINGER_RC=$?
if (( ! FINGER_RC ))
then
    FINGER_ENTRY="$(print ${FINGERPRINT} | awk '{print $1,$2,$4}')"
    log "${FINGER_USER}->${FINGER_ENTRY}"
    print "${FINGER_USER} ${FINGER_ENTRY}" >> "${LOCAL_DIR}/fingerprints"
else
    die "failed to obtain fingerprint for key ${FINGER_LINE} [RC=${FINGER_RC}]"
fi
# check bit count
case "${FINGERPRINT}" in
    1024*)
        KEY_1024_COUNT=$(( KEY_1024_COUNT + 1 ))
        ;;
    2048*)
        KEY_2048_COUNT=$(( KEY_2048_COUNT + 1 ))
        ;;
    4096*)
        KEY_4096_COUNT=$(( KEY_4096_COUNT + 1 ))
        ;;
    *)
        KEY_OTHER_COUNT=$(( KEY_OTHER_COUNT + 1 ))
        ;;
esac
        
return 0
}

# -----------------------------------------------------------------------------
# wait for child processes to exit
function wait_for_children
{
WAIT_ERRORS=0

# 'endless' loop :-)
while :
do
    (( ARG_DEBUG )) && print -u2 "child processes remaining: $*"
    for PID in "$@"
    do
        shift
        # child is still alive?
        if $(kill -0 ${PID} 2>/dev/null)
        then
            (( ARG_DEBUG )) && print -u2 "DEBUG: ${PID} is still alive"
            set -- "$@" "${PID}"
        # wait for sigchild, catching child exit codes is unreliable because
        # the child might have already ended before we get here (caveat emptor)
        elif $(wait ${PID})
        then
            log "child process ${PID} exited"
        else
            log "child process ${PID} exited"   
            WAIT_ERRORS=$(( WAIT_ERRORS + 1 ))
        fi
    done
    # break loop if we no child PIDs left
    (($# > 0)) || break
    sleep 1     # required to avoid race conditions
done

return ${WAIT_ERRORS}
}

# -----------------------------------------------------------------------------
function warn
{
NOW="$(date '+%d-%h-%Y %H:%M:%S')"

if [[ -n "$1" ]]
then
    if (( ARG_LOG ))
    then
        print - "$*" | while read LOG_LINE
        do
            # filter leading 'WARN:'
            LOG_LINE="${LOG_LINE#WARN: *}"
            print "${NOW}: WARN: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    if (( ARG_VERBOSE ))
    then
        print - "$*" | while read LOG_LINE
        do
            # filter leading 'WARN:'
            LOG_LINE="${LOG_LINE#WARN: *}"
            print "WARN:" "${LOG_LINE}"
        done
    fi
fi

return 0
}


#******************************************************************************
# MAIN routine
#******************************************************************************

# parse arguments/parameters
CMD_LINE="$@"
for PARAMETER in ${CMD_LINE}
do
    case ${PARAMETER} in
        -a|-apply|--apply)
            ARG_ACTION=1
            ;;
        -b|-backup|--backup)
            ARG_ACTION=9
            ;;
        -c|-copy|--copy)
            ARG_ACTION=2
            ;;
        -debug|--debug)
            ARG_DEBUG=1
            ;;
        -d|-distribute|--distribute)
            ARG_ACTION=2
            ;;
        -p|--preview-global|-preview-global)
            ARG_ACTION=7
            ;;
        -s|--check-syntax|-check-syntax)
            ARG_ACTION=8
            ;;
        -fix-local|--fix-local)
            ARG_ACTION=5
            ;;
        -fix-remote|--fix-remote)
            ARG_ACTION=6
            ;;
        -m|-make-finger|--make-finger)
            ARG_ACTION=3
            ;;
        -u|-update|--update)
            ARG_ACTION=4
            ;;
        -create-dir|--create-dir)
            FIX_CREATE=1
            ;;
        -fix-dir=*)
            ARG_FIX_DIR="${PARAMETER#-fix-dir=}"
            ;;
        --fix-dir=*)
            ARG_FIX_DIR="${PARAMETER#--fix-dir=}"
            ;;
        -local-dir=*)
            ARG_LOCAL_DIR="${PARAMETER#-local-dir=}"
            ;;
        --local-dir=*)
            ARG_LOCAL_DIR="${PARAMETER#--local-dir=}"
            ;;
        -log-dir=*)
            ARG_LOG_DIR="${PARAMETER#-log-dir=}"
            ;;
        --log-dir=*)
            ARG_LOG_DIR="${PARAMETER#--log-dir=}"
            ;;
        -no-log|--no-log)
            ARG_LOG=0
            ;;
        -remote-dir=*)
            ARG_REMOTE_DIR="${PARAMETER#-remote-dir=}"
            ;;
        --remote-dir=*)
            ARG_REMOTE_DIR="${PARAMETER#--remote-dir=}"
            ;;
        -targets=*)
            ARG_TARGETS="${PARAMETER#-targets=}"
            ;;
        --targets=*)
            ARG_TARGETS="${PARAMETER#--targets=}"
            ;;
        -V|-version|--version)
            print "INFO: $0: ${MY_VRF}"
            exit 0
            ;;
        \? | -h | -help | --help)
            display_usage
            exit 0
            ;;
    esac    
done

# startup checks
check_params && check_config && check_setup && check_logging

# catch shell signals
trap 'do_cleanup; exit' 1 2 3 15

log "*** start of ${SCRIPT_NAME} [${CMD_LINE}] ***"    
(( ARG_LOG )) && log "logging takes places in ${LOG_FILE}"  

log "runtime info: LOCAL_DIR is set to: ${LOCAL_DIR}"

case ${ARG_ACTION} in
    1)  # apply SSH controls remotely
        log "ACTION: apply SSH controls remotely"
        check_root_user && die "must NOT be run as user 'root'"
        # build clients list (in array)
        cat "${TARGETS_FILE}" | grep -v -E -e '^#' -e '^$' |\
        {
            I=0
            set -A CLIENTS
            while read LINE
            do
                CLIENTS[${I}]="${LINE}"
                I=$(( I + 1 ))
            done
        }
        # set max updates in background
        COUNT=${MAX_BACKGROUND_PROCS}
        for CLIENT in ${CLIENTS[@]}
        do
            update2host ${CLIENT} &
            PID=$!
            log "updating ${CLIENT} in background [PID=${PID}] ..."
            # add PID to list of all child PIDs
            PIDS="${PIDS} ${PID}"
            COUNT=$(( COUNT - 1 ))
            if (( COUNT <= 0 ))
            then
                # wait until all background processes are completed
                wait_for_children ${PIDS} || \
                    warn "$? background jobs failed to complete correctly"
                PIDS=''  
                # reset max updates in background
                COUNT=${MAX_BACKGROUND_PROCS}
            fi
        done
        # final wait for background processes to be finished completely
        wait_for_children ${PIDS} || \
            warn "$? background jobs failed to complete correctly"      

        log "finished applying SSH controls remotely"
        ;;
    2)  # copy/distribute SSH controls
        log "ACTION: copy/distribute SSH controls"
        check_root_user && die "must NOT be run as user 'root'"
        # build clients list (in array)
        cat "${TARGETS_FILE}" | grep -v -E -e '^#' -e '^$' |\
        {
            I=0
            set -A CLIENTS
            while read LINE
            do
                CLIENTS[${I}]="${LINE}"
                I=$(( I + 1 ))
            done
        }
        # set max updates in background
        COUNT=${MAX_BACKGROUND_PROCS}
        for CLIENT in ${CLIENTS[@]}
        do
            distribute2host ${CLIENT} &
            PID=$!
            log "copying/distributing to ${CLIENT} in background [PID=${PID}] ..."
            # add PID to list of all child PIDs
            PIDS="${PIDS} ${PID}"
            COUNT=$(( COUNT - 1 ))
            if (( COUNT <= 0 ))
            then
                # wait until all background processes are completed
                wait_for_children ${PIDS} || \
                    warn "$? background jobs failed to complete correctly"
                PIDS=''
                # reset max updates in background
                COUNT=${MAX_BACKGROUND_PROCS}               
            fi
        done
        # final wait for background processes to be finished completely
        wait_for_children ${PIDS} || \
            warn "$? background jobs failed to complete correctly"
        log "finished copying/distributing SSH controls"
        ;;
    3)  # create key fingerprints
        check_root_user && die "must NOT be run as user 'root'"
        log "ACTION: create key fingerprints into ${LOCAL_DIR}/fingerprints"
        > "${LOCAL_DIR}/fingerprints"

        # are keys stored in a file or a directory?
        if [[ -n "${KEYS_DIR}" ]]
        then
            cat ${KEYS_DIR}/* | sort | while read LINE
            do
                update_fingerprints "${LINE}"
                KEY_COUNT=$(( KEY_COUNT + 1 ))
            done 
        else
            while read LINE
            do
                update_fingerprints "${LINE}"
            done < ${KEYS_FILE}
        fi
        log "${KEY_COUNT} public keys discovered with following bits distribution:"
        log "   1024 bits: ${KEY_1024_COUNT}"
        log "   2048 bits: ${KEY_2048_COUNT}"
        log "   4096 bits: ${KEY_4096_COUNT}"
        log "   others   : ${KEY_OTHER_COUNT}"
        log "finished updating public key fingerprints"
        ;;
    4)  # apply SSH controls locally (root user)
        log "ACTION: apply SSH controls locally"
        log "$(sudo -n ${LOCAL_DIR}/update_ssh.pl ${SSH_UPDATE_OPTS})"
        # no error checking possible here due to log(), done in called script
        log "finished applying SSH controls locally"
        ;;
    5)  # fix local directory structure/perms/ownerships
        log "ACTION: fix local SSH controls repository"
        check_root_user || die "must be run as user 'root'"
        if (( FIX_CREATE ))
        then
            log "you requested to create directories (if needed)"
        else
            log "you requested NOT to create directories (if needed)"       
        fi
        
        # check if the SSH control repo is already there
        if [[ ${FIX_CREATE} = 1 && ! -d "${FIX_DIR}" ]]
        then    
            # create stub directories
            mkdir -p "${FIX_DIR}/holding" 2>/dev/null || \
                warn "failed to create directory ${FIX_DIR}/holding"
            mkdir -p "${FIX_DIR}/keys.d" 2>/dev/null || \
                warn "failed to create directory ${FIX_DIR}/keys.d"
        fi
        # fix permissions & ownerships
        if [[ -d "${FIX_DIR}" ]]
        then
            # updating default directories
            chmod 755 "${FIX_DIR}" 2>/dev/null && \
                chown root:sys "${FIX_DIR}" 2>/dev/null
            if [[ -d "${FIX_DIR}/holding" ]]
            then
                chmod 2775 "${FIX_DIR}/holding" 2>/dev/null && \
                    chown root:${SSH_OWNER_GROUP} "${FIX_DIR}/holding" 2>/dev/null
            fi                  
            if [[ -d "${FIX_DIR}/keys.d" ]]
            then
                chmod 755 "${FIX_DIR}/keys.d" 2>/dev/null && \
                    chown root:sys "${FIX_DIR}/keys.d" 2>/dev/null
            fi
            # checking files in holding (keys.d/* are fixed by update_ssh.pl)
            for FILE in access alias keys update_ssh.conf
            do
                if [[ -f "${FIX_DIR}/holding/${FILE}" ]]
                then
                    chmod 660 "${FIX_DIR}/holding/${FILE}" 2>/dev/null && \
                        chown root:${SSH_OWNER_GROUP} "${FIX_DIR}/holding/${FILE}" 2>/dev/null
                fi
            done
            for FILE in manage_ssh.sh update_ssh.pl
            do
                if [[ -f "${FIX_DIR}/holding/${FILE}" ]]
                then
                    chmod 770 "${FIX_DIR}/holding/${FILE}" 2>/dev/null && \
                        chown root:${SSH_OWNER_GROUP} "${FIX_DIR}/holding/${FILE}" 2>/dev/null
                fi
            done
            # log file
            if [[ -f "${LOG_FILE}" ]]
            then
                chmod 664 "${LOG_FILE}" 2>/dev/null && \
                    chown root:${SSH_OWNER_GROUP} "${LOG_FILE}" 2>/dev/null
            fi
            # check for SELinux labels
            case ${OS_NAME} in
                *Linux*)
                    case "$(getenforce)" in
                        *Permissive*|*Enforcing*)
                            LINUX_VERSION=$(get_linux_version)
                            case "${LINUX_VERSION}" in
                                5)
                                    chcon -R -t sshd_key_t "${FIX_DIR}/keys.d"
                                    ;;
                                6|7)
                                    chcon -R -t ssh_home_t "${FIX_DIR}/keys.d"
                                    ;;
                                *)
                                    chcon -R -t etc_t "${FIX_DIR}/keys.d"
                                    ;;
                            esac
                            ;;
                        *Disabled*)
                            :
                            ;;
                    esac
                    ;;
                *)
                    :
                    ;;
            esac
        else
            die "SSH controls repository at "${FIX_DIR}" does not exist?"
        fi
        log "finished applying fixes to the local SSH control repository"
        ;;
    6)  # fix remote directory structure/perms/ownerships
        log "ACTION: fix remote SSH controls repository"
        check_root_user && die "must NOT be run as user 'root'"
        # derive SSH controls repo from $REMOTE_DIR: 
        # /etc/ssh_controls/holding -> /etc/ssh_controls 
        FIX_DIR="$(print ${REMOTE_DIR%/*})"
        [[ -z "${FIX_DIR}" ]] && \
            die "could not determine SSH controls repo path from \$REMOTE_DIR?"
        # build clients list (in array)
        cat "${TARGETS_FILE}" | grep -v -E -e '^#' -e '^$' |\
        {
            I=0
            set -A CLIENTS
            while read LINE
            do
                CLIENTS[${I}]="${LINE}"
                I=$(( I + 1 ))
            done
        }
        # set max updates in background
        COUNT=${MAX_BACKGROUND_PROCS}
        for CLIENT in ${CLIENTS[@]}
        do
            fix2host ${CLIENT} "${FIX_DIR}" &
            PID=$!
            log "copying/distributing to ${CLIENT} in background [PID=${PID}] ..."
            # add PID to list of all child PIDs
            PIDS="${PIDS} ${PID}"
            COUNT=$(( COUNT - 1 ))
            if (( COUNT <= 0 ))
            then
                # wait until all background processes are completed
                wait_for_children ${PIDS} || \
                    warn "$? background jobs failed to complete correctly"
                PIDS=''
                # reset max updates in background
                COUNT=${MAX_BACKGROUND_PROCS}
            fi
        done
        # final wait for background processes to be finished completely
        wait_for_children ${PIDS} || \
            warn "$? background jobs failed to complete correctly"
        log "finished applying fixes to the remote SSH control repository"
        ;;
    7)  # dump the configuration namespace
        log "ACTION: dumping the global access namespace with resolved aliases ..."
        ${LOCAL_DIR}/update_ssh.pl --preview --global
        log "finished dumping the global namespace"
        ;;
    8)  # check syntax of the access/alias/keys files
        log "ACTION: syntax-checking the configuration files ..."
        check_syntax
        log "finished syntax-checking the configuration files"
        ;;
    9)  # make backup copy of configuration & keys files
        log "ACTION: backing up the current configuration & keys files ..."
        if [[ -d ${BACKUP_DIR} ]]
        then
            TIMESTAMP="$(date '+%Y%m%d-%H%M')"
            BACKUP_TAR_FILE="${BACKUP_DIR}/backup_repo_${TIMESTAMP}.tar"
            if [ \( -f ${BACKUP_TAR_FILE} \) -o \( -f "${BACKUP_TAR_FILE}.gz" \) ]
            then
                die "backup file ${BACKUP_TAR_FILE}(.gz) already exists"
            fi
            # keys files
            if [[ -n "${KEYS_DIR}" ]]
            then
                log "$(tar -cvf ${BACKUP_TAR_FILE} ${KEYS_DIR} 2>/dev/null)"
            else
                log "$(tar -cvf ${BACKUP_TAR_FILE} ${KEYS_FILE} 2>/dev/null)"   
            fi
            # configuration files
            for FILE in "${LOCAL_DIR}/access" "${LOCAL_DIR}/alias ${LOCAL_DIR}/targets"
            do
                log "$(tar -rvf ${BACKUP_TAR_FILE} ${FILE} 2>/dev/null)"
            done
            log "$(gzip ${BACKUP_TAR_FILE} 2>/dev/null)"
            log "resulting backup file is: $(ls -1 ${BACKUP_TAR_FILE}* 2>/dev/null)"
        else
            die "could not find backup directory ${BACKUP_DIR}. Host is not an SSH master?"
        fi
        log "finished backing up the current configuration & keys files"
        ;;
esac

# finish up work
do_cleanup

#******************************************************************************
# END of script
#******************************************************************************
