#!/usr/bin/env ksh
#******************************************************************************
# @(#) manage_ssh.sh
#******************************************************************************
# @(#) Copyright (C) 2014 by KUDOS BVBA (info@kudos.be).  All rights reserved.
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
#       remote, create SSH key fingerprints, distribute the SSH controls files,
#       discover SSH host keys.
# EXPECTS: (see --help for more options)
# REQUIRES: check_config(), check_logging(), check_params(), check_root_user(),
#           check_setup(), check_syntax(), count_fields(), die(), display_usage(),
#           distribute2host(), distribute2slave(), do_cleanup(), fix2host(),
#           fix2slave(), get_linux_name(), get_linux_version(), log(), logc(),
#           resolve_host(), sftp_file(),  start_ssh_agent(), stop_ssh_agent(),
#           update2host(), update2slave(), update_fingerprints(),
#           wait_for_children(), warn()
#           For other pre-requisites see the documentation in display_usage()
#
# -----------------------------------------------------------------------------
# DO NOT CHANGE THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING!
#******************************************************************************

#******************************************************************************
# DATA structures
#******************************************************************************

# ------------------------- CONFIGURATION starts here -------------------------
# Below configuration values should not be changed. Use the GLOBAL_CONFIG_FILE
# or LOCAL_CONFIG_FILE instead

# define the V.R.F (version/release/fix)
MY_VRF="1.7.0"
# name of the global configuration file (script)
GLOBAL_CONFIG_FILE="manage_ssh.conf"
# name of the local configuration file (script)
LOCAL_CONFIG_FILE="manage_ssh.conf.local"
# location of temporary working storage
TMP_DIR="/var/tmp"
# ------------------------- CONFIGURATION ends here ---------------------------
# miscelleaneous
PATH=${PATH}:/usr/bin:/usr/local/bin
SCRIPT_NAME="$(basename $0)"
SCRIPT_DIR="$(dirname $0)"
OS_NAME="$(uname)"
HOST_NAME="$(hostname)"
KEYS_FILE=""
KEYS_DIR=""
TARGETS_FILE=""
DO_SLAVE=0
FIX_CREATE=0
CAN_DISCOVER_KEYS=0
CAN_START_AGENT=1
KEY_COUNT=0
KEY_1024_COUNT=0
KEY_2048_COUNT=0
KEY_4096_COUNT=0
KEY_OTHER_COUNT=0
SSH_KEYGEN_OPTS=""
TMP_FILE="${TMP_DIR}/.${SCRIPT_NAME}.$$"
TMP_RC_FILE="${TMP_DIR}/.${SCRIPT_NAME}.rc.$$"
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
        print -u2 "ERROR: no value for the SSH_TRANSFER_USER setting in the configuration file"
        exit 1
    fi
fi
# LOCAL_DIR
if [[ -z "${LOCAL_DIR}" ]]
then
    print -u2 "ERROR: no value for the LOCAL_DIR setting in the configuration file"
    exit 1
fi
# REMOTE_DIR
if [[ -z "${REMOTE_DIR}" ]]
then
    print -u2 "ERROR: no value for the REMOTE_DIR setting in the configuration file"
    exit 1
fi
# DO_SFTP_CHMOD
if [[ -z "${DO_SFTP_CHMOD}" ]]
then
    print -u2 "ERROR: no value for the DO_SFTP_CHMOD setting in the configuration file"
    exit 1
fi
# SSH_UPDATE_USER
if [[ -z "${SSH_UPDATE_USER}" ]]
then
    SSH_UPDATE_USER="${LOGNAME}"
    if [[ -z "${SSH_UPDATE_USER}" ]]
    then
        print -u2 "ERROR: no value for SSH_UPDATE_USER setting in the configuration file"
        exit 1
    fi
fi
# SSH_KEYSCAN_BIN
if [[ -z "${SSH_KEYSCAN_BIN}" ]]
then
    print -u2 "ERROR: no value for the SSH_KEYSCAN_BIN setting in the configuration file"
    exit 1
fi
# DO_SSH_AGENT
if [[ -z "${DO_SSH_AGENT}" ]]
then
    print -u2 "ERROR:no value for the DO_SSH_AGENT setting in the configuration file"
    exit 1
fi
# MAX_BACKGROUND_PROCS
if [[ -z "${MAX_BACKGROUND_PROCS}" ]]
then
    print -u2 "ERROR: no value for the MAX_BACKGROUND_PROCS setting in the configuration file"
    exit 1
fi
# BACKUP_DIR
if [[ -z "${BACKUP_DIR}" ]]
then
    print -u2 "ERROR: no value for the BACKUP_DIR setting in the configuration file"
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
if (( ARG_ACTION < 1 || ARG_ACTION > 10 ))
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
    if [[ ! -d "${ARG_LOCAL_DIR}" ]] || [[ ! -r "${ARG_LOCAL_DIR}" ]]
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
# --slave
if (( DO_SLAVE ))
then
    # requires a list of targets (=slave servers)
    [[ -n "${ARG_TARGETS}" ]] || {
        print -u2 "ERROR: you must specify a list of targets with the --slave option"
        exit 1
    }
fi
# --targets
if [[ -n "${ARG_TARGETS}" ]]
then
    : > ${TMP_FILE}
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
(IFS='()'; set -- "$(id)"; print $2) | read UID
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
if (( ARG_ACTION == 1 || ARG_ACTION == 2 || ARG_ACTION == 6 || ARG_ACTION == 10 ))
then
    if [[ -z "${ARG_TARGETS}" ]]
    then
        TARGETS_FILE="${LOCAL_DIR}/targets"
        if [[ ! -r "${TARGETS_FILE}" ]]
        then
            print -u2 "ERROR: cannot read file ${TARGETS_FILE}"
            print -u2 "ERROR: possibly this is not a master or slave server"
            exit 1
        fi
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
                "${SCRIPT_DIR}/${SCRIPT_NAME}" \
                "${SCRIPT_DIR}/${GLOBAL_CONFIG_FILE}"
    do
        if [[ ! -r "${FILE}" ]]
        then
            print -u2 "ERROR: cannot read file ${FILE}"
            exit 1
        fi
    done
fi
# check if 'ssh-keyscan' exists
if [[ ! -x "${SSH_KEYSCAN_BIN}" ]]
then
    print -u2 "WARN: 'ssh-keyscan' tool not found, host key discovery is not possible"
    CAN_DISCOVER_KEYS=0
fi
# check for SSH agent pre-requisites
if (( DO_SSH_AGENT ))
then
    # ssh-agent
    which ssh-agent >/dev/null 2>/dev/null
    if (( $? ))
    then
        print -u2 "WARN: ssh-agent not available on ${HOST_NAME}"
        CAN_START_AGENT=0
    fi
    # private key
    if [[ ! -r "${SSH_PRIVATE_KEY}" ]]
    then
        print -u2 "WARN: SSH private key not found ${SSH_PRIVATE_KEY}, ssh-agent disabled"
        CAN_START_AGENT=0
    fi
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

print ${NUM_FIELDS}

return 0
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
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*)
                    LOG_LINE="${LOG_LINE#INFO: *}"
                    LOG_SIGIL="INFO"
                    ;;
                WARN:*)
                    LOG_LINE="${LOG_LINE#WARN: *}"
                    LOG_SIGIL="WARN"
                    ;;
                ERROR:*)
                    LOG_LINE="${LOG_LINE#ERROR: *}"
                    LOG_SIGIL="ERROR"
                    ;;
                *)
                    LOG_SIGIL="ERROR"
                    ;;
            esac
            print "${NOW}: ${LOG_SIGIL}: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    print - "$*" | while read LOG_LINE
    do
        # check for leading log sigils and retain them
        case "${LOG_LINE}" in
            INFO:*|WARN:*|ERROR*)
                print "${LOG_LINE}"
                ;;
            *)
                print "ERROR:" "${LOG_LINE}"
                ;;
        esac
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
            (--apply [--slave] [--remote-dir=<remote_directory>] [--targets=<host1>,<host2>,...]) |
                ((--copy|--distribute) [--slave] [--remote-dir=<remote_directory> [--targets=<host1>,<host2>,...]]) |
                    (--discover [--targets=<host1>,<host2>,...]) |
                        ([--fix-local --fix-dir=<repository_dir> [--create-dir]] | [--fix-remote [--slave] [--create-dir] [--targets=<host1>,<host2>,...]])
                            [--local-dir=<local_directory>] [--no-log] [--log-dir=<log_directory>] [--debug]

Parameters:

--apply|-a          : apply SSH controls remotely (~targets)
--backup|-b         : create a backup of the SSH controls repository (SSH master)
--check-syntax|-s   : do basic syntax checking on SSH controls configuration
                      (access, alias & keys files)
--copy|-c           : copy SSH control files to remote host (~targets)
--create-dir        : also create missing directories when fixing the SSH controls
                      repository (see also --fix-local/--fix-remote)
--debug             : print extra status messages on STDERR
--discover|-d       : discover SSH host keys (STDOUT)
--distribute        : same as --copy
--fix-dir           : location of the local SSH controls client repository
--fix-local         : fix permissions on the local SSH controls repository
                      (local SSH controls repository given by --fix-dir)
--fix-remote        : fix permissions on the remote SSH controls repository
--help|-h           : this help text
--local-dir         : location of the SSH control files on the local filesystem.
                      [default: see LOCAL_DIR setting]
--log-dir           : specify a log directory location.
--no-log            : do not log any messages to the script log file.
--make-finger|-m    : create (local) key fingerprints file
--preview-global|-p : dump the global access namespace (after alias resolution)
--remote-dir        : directory where SSH control files are/should be
                      located/copied on/to the target host
                      [default: see REMOTE_DIR setting]
--slave             : perform actions in master->slave mode
--targets           : comma-separated list of target hosts to operate on. Override the
                      hosts contained in the 'targets' configuration file.
--update|-u         : apply SSH controls locally

--version|-V        : show the script version/release/fix

Note 1: copy and apply actions are run in parallel across a maximum of clients
        at the same time [default: see MAX_BACKGROUND_PROCS setting]

Note 2: for fix and apply actions: make sure correct 'sudo' rules are setup
        on the target systems to allow the SSH controls script to run with
        elevated privileges.

Note 3: only GLOBAL configuration files will be distributed to target hosts.

EOT

return 0
}

# -----------------------------------------------------------------------------
# distribute SSH controls to a single host/client
function distribute2host
{
SERVER="$1"
ERROR_COUNT=0
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
            "${SCRIPT_DIR}/${SCRIPT_NAME}!770" \
            "${SCRIPT_DIR}/${GLOBAL_CONFIG_FILE}!660"
do
    # sftp transfer
    sftp_file ${FILE} ${SERVER}
    COPY_RC=$?
    if (( ! COPY_RC ))
    then
        log "transferred ${FILE%!*} to ${SERVER}:${REMOTE_DIR}"
    else
        warn "failed to transfer ${FILE%!*} to ${SERVER}:${REMOTE_DIR} [RC=${COPY_RC}]"
        ERROR_COUNT=$(( ERROR_COUNT + 1 ))
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
    sftp_file "${TMP_MERGE_FILE}!640" ${SERVER}
    COPY_RC=$?
    if (( ! COPY_RC ))
    then
        log "transferred ${TMP_MERGE_FILE} to ${SERVER}:${REMOTE_DIR}"
    else
        warn "failed to transfer ${TMP_MERGE_FILE%!*} to ${SERVER}:${REMOTE_DIR} [RC=${COPY_RC}]"
        ERROR_COUNT=$(( ERROR_COUNT + 1 ))
    fi
    [[ -d ${TMP_WORK_DIR} ]] && rm -rf ${TMP_WORK_DIR} 2>/dev/null
else
    sftp_file "${KEYS_FILE}!640" ${SERVER}
    COPY_RC=$?
    if (( ! COPY_RC ))
    then
        log "transferred ${KEYS_FILE} to ${SERVER}:${REMOTE_DIR}"
    else
        warn "failed to transfer ${KEYS_FILE} to ${SERVER}:${REMOTE_DIR} [RC=${COPY_RC}]"
        ERROR_COUNT=$(( ERROR_COUNT + 1 ))
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
            ERROR_COUNT=$(( ERROR_COUNT + 1 ))
        fi
    fi
fi

return ${ERROR_COUNT}
}


# -----------------------------------------------------------------------------
# distribute SSH controls to a single host in slave mode
function distribute2slave
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

log "copying SSH controls on ${SERVER} in slave mode, this may take a while ..."
( RC=0; ssh -A ${SSH_ARGS} ${SERVER} ${REMOTE_DIR}/${SCRIPT_NAME} --copy;
      print "$?" > ${TMP_RC_FILE}; exit
) 2>&1 | logc

# fetch return code from subshell
RC="$(< ${TMP_RC_FILE})"

return ${RC}
}

# -----------------------------------------------------------------------------
function do_cleanup
{
log "performing cleanup ..."

# remove temporary file(s)
[[ -f ${TMP_FILE} ]] && rm -f ${TMP_FILE} >/dev/null 2>&1
[[ -f ${TMP_MERGE_FILE} ]] && rm -f ${TMP_MERGE_FILE} >/dev/null 2>&1
[[ -f ${TMP_RC_FILE} ]] && rm -f ${TMP_RC_FILE} >/dev/null 2>&1
log "*** finish of ${SCRIPT_NAME} [${CMD_LINE}] /$$@${HOST_NAME}/ ***"

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
log "fixing SSH controls on ${SERVER} ..."
if [[ -z "${SSH_UPDATE_USER}" ]]
then
    # own user w/ sudo
    ( RC=0; ssh ${SSH_ARGS} ${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --fix-local --fix-dir=${SERVER_DIR};
      print "$?" > ${TMP_RC_FILE}; exit
    ) 2>&1 | logc
elif [[ "${SSH_UPDATE_USER}" != "root" ]]
then
    # other user w/ sudo
    ( RC=0; ssh ${SSH_ARGS} ${SSH_UPDATE_USER}@${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --fix-local --fix-dir=${SERVER_DIR};
      print "$?" > ${TMP_RC_FILE}; exit
    ) 2>&1 | logc
else
    # root user w/o sudo
    ( RC=0; ssh ${SSH_ARGS} root@${SERVER} ${REMOTE_DIR}/${SCRIPT_NAME} --fix-local --fix-dir=${SERVER_DIR};
      print "$?" > ${TMP_RC_FILE}; exit
    ) 2>&1 | logc
fi

# fetch return code from subshell
RC="$(< ${TMP_RC_FILE})"

return ${RC}
}

# -----------------------------------------------------------------------------
# fix SSH controls on a single host/client in slave mode (permissions/ownerships)
# !! requires appropriate 'sudo' rules on remote client for privilege elevation
function fix2slave
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

log "fixing SSH controls on ${SERVER} in slave mode, this may take a while ..."
( RC=0; ssh -A ${SSH_ARGS} ${SERVER} ${REMOTE_DIR}/${SCRIPT_NAME} --fix-remote --fix-dir=${SERVER_DIR};
    print "$?" > ${TMP_RC_FILE}; exit
) 2>&1 | logc

# fetch return code from subshell
RC="$(< ${TMP_RC_FILE})"

return ${RC}
}

# -----------------------------------------------------------------------------
function get_linux_name
{
LSB_NAME="$(lsb_release -is 2>/dev/null | cut -f2 -d':')"

print "${LSB_NAME}"

return 0
}

# -----------------------------------------------------------------------------
function get_linux_version
{
LSB_VERSION="$(lsb_release -rs 2>/dev/null | cut -f1 -d'.')"

if [[ -z "${LSB_VERSION}" ]]
then
    RELEASE_STRING="$(grep -i 'release' /etc/redhat-release 2>/dev/null)"

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

return 0
}

# -----------------------------------------------------------------------------
# log an INFO: message (via ARG).
function log
{
NOW="$(date '+%d-%h-%Y %H:%M:%S')"

# log an INFO: message (via ARG).
if [[ -n "$1" ]]
then
    if (( ARG_LOG ))
    then
        print - "$*" | while read LOG_LINE
        do
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*)
                    LOG_LINE="${LOG_LINE#INFO: *}"
                    LOG_SIGIL="INFO"
                    ;;
                WARN:*)
                    LOG_LINE="${LOG_LINE#WARN: *}"
                    LOG_SIGIL="WARN"
                    ;;
                ERROR:*)
                    LOG_LINE="${LOG_LINE#ERROR: *}"
                    LOG_SIGIL="ERROR"
                    ;;
                *)
                    LOG_SIGIL="INFO"
                    ;;
            esac
            print "${NOW}: ${LOG_SIGIL}: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    if (( ARG_VERBOSE ))
    then
        print - "$*" | while read LOG_LINE
        do
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*|WARN:*|ERROR*)
                    print "${LOG_LINE}"
                    ;;
                *)
                    print "INFO:" "${LOG_LINE}"
                    ;;
            esac
        done
    fi
fi

return 0
}

# -----------------------------------------------------------------------------
# log an INFO: message (via STDIN). Do not use when STDIN is still open
# shellcheck disable=SC2120
function logc
{
NOW="$(date '+%d-%h-%Y %H:%M:%S')"
LOG_STDIN=""

# process STDIN (if any)
[[ ! -t 0 ]] && LOG_STDIN="$(cat)"
if [[ -n "${LOG_STDIN}" ]]
then
    if (( ARG_LOG ))
    then
        print - "${LOG_STDIN}" | while read LOG_LINE
        do
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*)
                    LOG_LINE="${LOG_LINE#INFO: *}"
                    LOG_SIGIL="INFO"
                    ;;
                WARN:*)
                    LOG_LINE="${LOG_LINE#WARN: *}"
                    LOG_SIGIL="WARN"
                    ;;
                ERROR:*)
                    LOG_LINE="${LOG_LINE#ERROR: *}"
                    LOG_SIGIL="ERROR"
                    ;;
                *)
                    LOG_SIGIL="INFO"
                    ;;
            esac
            print "${NOW}: ${LOG_SIGIL}: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    if (( ARG_VERBOSE ))
    then
        print - "${LOG_STDIN}" | while read LOG_LINE
        do
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*|WARN:*|ERROR*)
                    print "${LOG_LINE}"
                    ;;
                *)
                    print "INFO:" "${LOG_LINE}"
                    ;;
            esac
        done
    fi
fi

# process ARG (if any)
if [[ -n "$1" ]]
then
    if (( ARG_LOG != 0 ))
    then
        print - "$*" | while read LOG_LINE
        do
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*)
                    LOG_LINE="${LOG_LINE#INFO: *}"
                    LOG_SIGIL="INFO"
                    ;;
                WARN:*)
                    LOG_LINE="${LOG_LINE#WARN: *}"
                    LOG_SIGIL="WARN"
                    ;;
                ERROR:*)
                    LOG_LINE="${LOG_LINE#ERROR: *}"
                    LOG_SIGIL="ERROR"
                    ;;
                *)
                    LOG_SIGIL="INFO"
                    ;;
            esac
            print "${NOW}: ${LOG_SIGIL}: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    if (( ARG_VERBOSE != 0 ))
    then
        print - "$*" | while read LOG_LINE
        do
            case "${LOG_LINE}" in
                INFO:*|WARN:*|ERROR*)
                    print "${LOG_LINE}"
                    ;;
                *)
                    print "INFO:" "${LOG_LINE}"
                    ;;
            esac
        done
    fi
fi

return 0
}

# -----------------------------------------------------------------------------
# resolve a host (check)
function resolve_host
{
nslookup "$1" 2>/dev/null | grep -q -E -e 'Address:.*([0-9]{1,3}[\.]){3}[0-9]{1,3}'

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
# shellcheck disable=SC2164
OLD_PWD=$(pwd)
cd ${TRANSFER_DIR} || return 1

# transfer, (possibly) chmod the file to/on the target server (keep STDERR)
if (( DO_SFTP_CHMOD ))
then
    sftp ${SFTP_ARGS} ${SSH_TRANSFER_USER}@${TRANSFER_HOST} >/dev/null <<EOT
cd ${REMOTE_DIR}
put ${SOURCE_FILE}
chmod ${TRANSFER_PERMS} ${SOURCE_FILE}
EOT
    SFTP_RC=$?
else
    sftp ${SFTP_ARGS} ${SSH_TRANSFER_USER}@${TRANSFER_HOST} >/dev/null <<EOT
cd ${REMOTE_DIR}
put ${SOURCE_FILE}
EOT
    SFTP_RC=$?
fi

cd ${OLD_PWD} || return 1

return ${SFTP_RC}
}

# -----------------------------------------------------------------------------
# start a SSH agent
function start_ssh_agent
{
log "requested to start an SSH agent on ${HOST_NAME} ..."

# is there one still running, then we re-use it
if [[ -n "${SSH_AGENT_PID}" ]]
then
    log "SSH agent already running on ${HOST_NAME} with PID: ${SSH_AGENT_PID}"
else
    # start the SSH agent
    eval "$(ssh-agent)" >/dev/null 2>/dev/null

    if [[ -z "${SSH_AGENT_PID}" ]]
    then
        warn "unable to start SSH agent on ${HOST_NAME}"
        return 1
    else
        log "SSH agent started on ${HOST_NAME}:"
        log "$(ps -fp ${SSH_AGENT_PID})"
    fi
fi

# add the private key
log "adding private key ${SSH_PRIVATE_KEY} to SSH agent on ${HOST_NAME} ..."
log "$(ssh-add ${SSH_PRIVATE_KEY} 2>&1)"
if (( $? ))
then
    warn "unable to add SSH private key to SSH agent on ${HOST_NAME}"
    return 1
fi

return 0
}

# -----------------------------------------------------------------------------
function stop_ssh_agent
{
# stop the SSH agent
log "stopping SSH agent (if needed) on ${HOST_NAME} ..."

if [[ -n "${SSH_AGENT_PID}" ]]
then
    # SIGTERM
    log "stopping (TERM) process on ${HOST_NAME} with PID: ${SSH_AGENT_PID}"
    log "$(ps -fp ${SSH_AGENT_PID})"
    kill -s TERM ${SSH_AGENT_PID}
    sleep 3

    # SIGKILL
    if (( $(pgrep -u "${USER}" ssh-agent | grep -c "${SSH_AGENT_PID}") ))
    then
        log "stopping (KILL) process on ${HOST_NAME} with PID: ${SSH_AGENT_PID}"
        log "$(ps -fp ${SSH_AGENT_PID})"
        kill -s kill ${SSH_AGENT_PID}
    fi
    sleep 3
else
    log "no SSH agent running on ${HOST_NAME}"
fi

# process check
if (( $(pgrep -u "${USER}" ssh-agent | grep -c "${SSH_AGENT_PID}") ))
then
    warn "unable to stop running SSH agent on ${HOST_NAME} [PID=${SSH_AGENT_PID}]"
    return 1
fi

return 0
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
    ( RC=0; ssh ${SSH_ARGS} ${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --update;
      print "$?" > ${TMP_RC_FILE}; exit
    ) 2>&1 | logc
elif [[ "${SSH_UPDATE_USER}" != "root" ]]
then
    # other user w/ sudo
    ( RC=0; ssh ${SSH_ARGS} ${SSH_UPDATE_USER}@${SERVER} sudo -n ${REMOTE_DIR}/${SCRIPT_NAME} --update;
      print "$?" > ${TMP_RC_FILE}; exit
    ) 2>&1 | logc
else
    # root user w/o sudo
    ( RC=0; ssh ${SSH_ARGS} root@${SERVER} ${REMOTE_DIR}/${SCRIPT_NAME} --update;
      print "$?" > ${TMP_RC_FILE}; exit
    ) 2>&1 | logc
fi

# fetch return code from subshell
RC="$(< ${TMP_RC_FILE})"

return ${RC}
}

# -----------------------------------------------------------------------------
# update SSH controls on a single host/client in slave mode
function update2slave
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

log "applying ssh controls on ${SERVER} in slave mode, this may take a while ..."
( RC=0; ssh -A ${SSH_ARGS} ${SERVER} ${REMOTE_DIR}/${SCRIPT_NAME} --apply;
      print "$?" > ${TMP_RC_FILE}; exit
) 2>&1 | logc

# fetch return code from subshell
RC="$(< ${TMP_RC_FILE})"

return ${RC}
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
(( FINGER_FIELDS != 3 )) && die "line '${FINGER_LINE}' has missing or too many field(s) (should be 3))"

# create fingerprint
FINGER_USER="$(print ${FINGER_LINE} | awk -F, '{print $1}')"
print "${FINGER_LINE}" | awk -F, '{print $2 " " $3}' > ${TMP_FILE}
# check if fingerprint is valid
FINGERPRINT="$(ssh-keygen ${SSH_KEYGEN_OPTS} -l -f ${TMP_FILE} 2>&1)"
FINGER_RC=$?
if (( ! FINGER_RC ))
then
    case "${OS_NAME}" in
    HP-UX)
        FINGER_ENTRY="$(print ${FINGERPRINT} | awk '{print $1,$2,$4}')"
        ;;
    *)
        FINGER_ENTRY="$(print ${FINGERPRINT} | awk '{print $1,$2,$5}')"
        ;;
    esac
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
        if kill -0 ${PID} 2>/dev/null
        then
            (( ARG_DEBUG )) && print -u2 "DEBUG: ${PID} is still alive"
            set -- "$@" "${PID}"
        # wait for sigchild, catching child exit codes is unreliable because
        # the child might have already ended before we get here (caveat emptor)
        else
            wait ${PID}
            RC=$?
            if (( RC ))
            then
                warn "child process ${PID} exited [RC=${RC}]"
                WAIT_ERRORS=$(( WAIT_ERRORS + 1 ))
            else
                log "child process ${PID} exited [RC=${RC}]"
            fi
        fi
    done
    # break loop if we have no child PIDs left
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
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*)
                    LOG_LINE="${LOG_LINE#INFO: *}"
                    LOG_SIGIL="INFO"
                    ;;
                WARN:*)
                    LOG_LINE="${LOG_LINE#WARN: *}"
                    LOG_SIGIL="WARN"
                    ;;
                ERROR:*)
                    LOG_LINE="${LOG_LINE#ERROR: *}"
                    LOG_SIGIL="ERROR"
                    ;;
                *)
                    LOG_SIGIL="WARN"
                    ;;
            esac
            print "${NOW}: ${LOG_SIGIL}: [$$]:" "${LOG_LINE}" >>${LOG_FILE}
        done
    fi
    if (( ARG_VERBOSE ))
    then
        print - "$*" | while read LOG_LINE
        do
            # check for leading log sigils and retain them
            case "${LOG_LINE}" in
                INFO:*|WARN:*|ERROR*)
                    print "${LOG_LINE}"
                    ;;
                *)
                    print "WARN:" "${LOG_LINE}"
                    ;;
            esac
        done
    fi
fi

return 0
}


#******************************************************************************
# MAIN routine
#******************************************************************************

# parse arguments/parameters
CMD_LINE="$*"
for PARAMETER in ${CMD_LINE}
do
    case ${PARAMETER} in
        -a|-apply|--apply)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=1
            ;;
        -b|-backup|--backup)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=9
            ;;
        -c|-copy|--copy)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=2
            ;;
        -debug|--debug)
            ARG_DEBUG=1
            ;;
        -distribute|--distribute)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=2
            ;;
        -m|-make-finger|--make-finger)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=3
            ;;
        -d|-discover|--discover)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=10
            ARG_LOG=0
            ARG_VERBOSE=0
            CAN_DISCOVER_KEYS=1
            ;;
        -p|--preview-global|-preview-global)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=7
            ;;
        -fix-local|--fix-local)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=5
            ;;
        -fix-remote|--fix-remote)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=6
            ;;
        -s|-check-syntax|--check-syntax)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
            ARG_ACTION=8
            ;;
        -u|-update|--update)
            (( ARG_ACTION )) && {
                print -u2 "ERROR: multiple actions specified"
                exit 1
            }
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
        -slave|--slave)
            DO_SLAVE=1
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

# check for configuration files (local overrides local)
if [[ -r "${SCRIPT_DIR}/${GLOBAL_CONFIG_FILE}" || -r "${SCRIPT_DIR}/${LOCAL_CONFIG_FILE}" ]]
then
    if [[ -r "${SCRIPT_DIR}/${GLOBAL_CONFIG_FILE}" ]]
    then
        # shellcheck source=/dev/null
        . "${SCRIPT_DIR}/${GLOBAL_CONFIG_FILE}"
    fi
    if [[ -r "${SCRIPT_DIR}/${LOCAL_CONFIG_FILE}" ]]
    then
        # shellcheck source=/dev/null
        . "${SCRIPT_DIR}/${LOCAL_CONFIG_FILE}"
    fi
else
    print -u2 "ERROR: could not find global or local configuration file"
fi

# startup checks
check_params && check_config && check_setup && check_logging

# catch shell signals
trap 'do_cleanup; exit' 1 2 3 15

log "*** start of ${SCRIPT_NAME} [${CMD_LINE}] /$$@${HOST_NAME}/ ***"
(( ARG_LOG )) && log "logging takes places in ${LOG_FILE}"

log "runtime info: LOCAL_DIR is set to: ${LOCAL_DIR}"

case ${ARG_ACTION} in
    1)  # apply SSH controls remotely
        log "ACTION: apply SSH controls remotely"
        # check for root or non-root model
        if [[ "${SSH_UPDATE_USER}" != "root" ]]
        then
            check_root_user && die "must NOT be run as user 'root'"
        fi
        # start SSH agent (if needed)
        if (( DO_SSH_AGENT && CAN_START_AGENT ))
        then
            start_ssh_agent
            if (( $? ))
            then
                die "problem with launching an SSH agent, bailing out"
            fi
        fi
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
        for CLIENT in "${CLIENTS[@]}"
        do
            if (( DO_SLAVE ))
            then
                update2slave ${CLIENT} &
            else
                update2host ${CLIENT} &
            fi
            PID=$!
            log "updating ${CLIENT} in background [PID=${PID}] ..."
            # add PID to list of all child PIDs
            PIDS="${PIDS} ${PID}"
            COUNT=$(( COUNT - 1 ))
            if (( COUNT <= 0 ))
            then
                # wait until all background processes are completed
                wait_for_children ${PIDS} || \
                    warn "$? background jobs (possibly) failed to complete correctly"
                PIDS=''
                # reset max updates in background
                COUNT=${MAX_BACKGROUND_PROCS}
            fi
        done
        # final wait for background processes to be finished completely
        wait_for_children ${PIDS} || \
            warn "$? background jobs (possibly) failed to complete correctly"
        # stop SSH agent if needed
        (( DO_SSH_AGENT && CAN_START_AGENT )) && \
            stop_ssh_agent
        log "finished applying SSH controls remotely"
        ;;
    2)  # copy/distribute SSH controls
        log "ACTION: copy/distribute SSH controls"
        # check for root or non-root model
        if [[ "${SSH_TRANSFER_USER}" != "root" ]]
        then
            check_root_user && die "must NOT be run as user 'root'"
        fi
        # start SSH agent (if needed)
        if (( DO_SSH_AGENT && CAN_START_AGENT ))
        then
            start_ssh_agent
            if (( $? ))
            then
                die "problem with launching an SSH agent, bailing out"
            fi
        fi
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
        for CLIENT in "${CLIENTS[@]}"
        do
            if (( DO_SLAVE ))
            then
                distribute2slave ${CLIENT} &
            else
                distribute2host ${CLIENT} &
            fi
            PID=$!
            log "copying/distributing to ${CLIENT} in background [PID=${PID}] ..."
            # add PID to list of all child PIDs
            PIDS="${PIDS} ${PID}"
            COUNT=$(( COUNT - 1 ))
            if (( COUNT <= 0 ))
            then
                # wait until all background processes are completed
                wait_for_children ${PIDS} || \
                    warn "$? background jobs (possibly) failed to complete correctly"
                PIDS=''
                # reset max updates in background
                COUNT=${MAX_BACKGROUND_PROCS}
            fi
        done
        # final wait for background processes to be finished completely
        wait_for_children ${PIDS} || \
            warn "$? background jobs (possibly) failed to complete correctly"
        # stop SSH agent if needed
        (( DO_SSH_AGENT && CAN_START_AGENT )) && \
            stop_ssh_agent
        log "finished copying/distributing SSH controls"
        ;;
    3)  # create key fingerprints
        # check for root or non-root model
        if [[ "${SSH_UPDATE_USER}" != "root" ]]
        then
            check_root_user && die "must NOT be run as user 'root'"
        fi
        log "ACTION: create key fingerprints into ${LOCAL_DIR}/fingerprints"
        : > "${LOCAL_DIR}/fingerprints"

        # check fingerprint type
        if [[ -n "${FINGERPRINT_TYPE}" ]]
        then
            case "${FINGERPRINT_TYPE}" in
                md5|sha256|MD5|SHA256)
                    log "fingerprinting with type: ${FINGERPRINT_TYPE}"
                    ;;
                *)
                    die "unknown fingerprint type specified in the configuration file"
                    ;;
            esac
        else
            FINGERPRINT_TYPE="md5"
            log "fingerprinting with type: ${FINGERPRINT_TYPE}"
        fi

        # check if ssh-keygen support fingerprint type
        FAIL_SSH_KEYGEN=$(ssh-keygen -E 2>&1 | grep -c "illegal")
        if (( ! FAIL_SSH_KEYGEN ))
        then
            SSH_KEYGEN_OPTS="-E ${FINGERPRINT_TYPE}"
        else
            warn "ssh-keygen only supports MD5 fingerprinting, regardless of your choice"
        fi

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
        ( RC=0; ${LOCAL_DIR}/update_ssh.pl ${SSH_UPDATE_OPTS};
          print "$?" > ${TMP_RC_FILE}; exit
        ) 2>&1 | logc
        # fetch return code from subshell
        RC="$(< ${TMP_RC_FILE})"
        if (( RC ))
        then
            die "failed to apply SSH controls locally [RC=${RC}]"
        else
            log "finished applying SSH controls locally [RC=${RC}]"
        fi
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
        if (( FIX_CREATE )) && [[ ! -d "${FIX_DIR}" ]]
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
            for FILE in access alias keys ${GLOBAL_CONFIG_FILE} update_ssh.conf
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
                    LINUX_NAME="$(get_linux_name)"
                    LINUX_VERSION="$(get_linux_version)"
                    case ${LINUX_NAME} in
                        *Centos*|*RHEL*)
                            case "$(getenforce 2>/dev/null)" in
                                *Permissive*|*Enforcing*)
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
                    esac
                    ;;
                *)
                    :
                    ;;
            esac
        else
            die "SSH controls repository at ${FIX_DIR} does not exist?"
        fi
        log "finished applying fixes to the local SSH control repository"
        ;;
    6)  # fix remote directory structure/perms/ownerships
        log "ACTION: fix remote SSH controls repository"
        # check for root or non-root model
        if [[ "${SSH_UPDATE_USER}" != "root" ]]
        then
            check_root_user && die "must NOT be run as user 'root'"
        fi
        # start SSH agent (if needed)
        if (( DO_SSH_AGENT && CAN_START_AGENT ))
        then
            start_ssh_agent
            if (( $? ))
            then
                die "problem with launching an SSH agent, bailing out"
            fi
        fi
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
        for CLIENT in "${CLIENTS[@]}"
        do
            if (( DO_SLAVE ))
            then
                fix2slave ${CLIENT} "${FIX_DIR}" &
            else
                fix2host ${CLIENT} "${FIX_DIR}" &
            fi
            PID=$!
            log "fixing SSH controls on ${CLIENT} in background [PID=${PID}] ..."
            # add PID to list of all child PIDs
            PIDS="${PIDS} ${PID}"
            COUNT=$(( COUNT - 1 ))
            if (( COUNT <= 0 ))
            then
                # wait until all background processes are completed
                wait_for_children ${PIDS} || \
                    warn "$? background jobs (possibly) failed to complete correctly"
                PIDS=''
                # reset max updates in background
                COUNT=${MAX_BACKGROUND_PROCS}
            fi
        done
        # final wait for background processes to be finished completely
        wait_for_children ${PIDS} || \
            warn "$? background jobs (possibly) failed to complete correctly"
        # stop SSH agent if needed
        (( DO_SSH_AGENT && CAN_START_AGENT )) && \
            stop_ssh_agent
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
            if [[ -f ${BACKUP_TAR_FILE} ]] || [[ -f "${BACKUP_TAR_FILE}.gz" ]]
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
    10) # gather SSH host keys
        log "ACTION: gathering SSH host keys ..."
        if (( CAN_DISCOVER_KEYS ))
        then
            cat "${TARGETS_FILE}" | grep -v -E -e '^#' -e '^$' |\
                ${SSH_KEYSCAN_BIN} ${SSH_KEYSCAN_ARGS} -f -
        fi
        log "finished gathering SSH host keys"
        ;;
esac

# finish up work
do_cleanup

#******************************************************************************
# END of script
#******************************************************************************
