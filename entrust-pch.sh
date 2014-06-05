#!/bin/bash 

#------------------------------------------------------------
# entrust-pch.sh
# @2010
#------------------------------------------------------------

TMP_BASE=/tmp/base$$.ldif.tmp
TMP_EUSR=/tmp/eusr$$.ldif.tmp
TMP_EPCH=/tmp/politicas$$.pch
LDAP_HOST="ldap.seg-social.es"

#--------------------------------------------------------------------------------
# USED PROCS
#--------------------------------------------------------------------------------
MV=/bin/mv
RM=/bin/rm
AWK=/usr/bin/awk
GREP=/usr/bin/grep
PING=/usr/sbin/ping
DATE=/bin/date
CHOWN=/bin/chown
FIND=/usr/bin/find
SLEEP=/bin/sleep
ROUTE=/usr/sbin/route
PKILL=/usr/bin/pkill
CKSUM=/usr/bin/cksum
DIFF=/usr/bin/diff
LOGGER=/bin/logger
LDAPSEARCH=/usr/bin/ldapsearch


#--------------------------------------------------------------------------------
# GLOBAL VARIABLES
#--------------------------------------------------------------------------------
declare -a GLOBAL_TABLE


PCH_LINE_LEN=61 
LOGGER_PRIORITY="daemon.notice"
PROC_NAME="entrust-pch"
MSK_TIME="+%Y%m%d"


#--------------------------------------------------------------------------------
# TODO: MODIFIABLE SECTION
#--------------------------------------------------------------------------------
SHARED_DIR=/apps/ucm/prdi00web/w0/descargas
POLICY_NAME=politicas.pch
POLICY_EPCH=${SHARED_DIR}/${POLICY_NAME}
LOCK_FILE=${SHARED_DIR}/.entrust-pch.lock
BACK_RETENTION=10
USER=stuser
GROUP=webgroup
 

#--------------------------------------------------------------------------------
# @SYSLOG
# 
# @param $1: MESSAGE
# @return
# @desc Logs a message to syslog 
#--------------------------------------------------------------------------------
SYSLOG() {	
	MESG=$1
	${LOGGER} -p ${LOGGER_PRIORITY} -t ${PROC_NAME} ${MESG}
}

#--------------------------------------------------------------------------------
# @LDAP_EXCEPTION
# 
# @param $1: 
# @return
# @desc Logs a message to syslog 
#--------------------------------------------------------------------------------
LDAP_EXCEPTION() { 
	if [ $1 != 0 ]; then
		SYSLOG "LDAP QUERY EXCEPTION - Exiting!"
		exit 	
	fi
	
}

#--------------------------------------------------------------------------------
# @RANDON_WAIT
# 
# @param:  	NONE
# @return: 	NONE
# @desc: 	Wait some random time between 1-120 seconds.	
#--------------------------------------------------------------------------------
RANDON_WAIT() {
	TIMEOUT=$[ ( $RANDOM % 120 )  + 1 ]
	SYSLOG "WAITING ${TIMEOUT} seconds"
	${SLEEP} ${TIMEOUT}
}


#--------------------------------------------------------------------------------
# @LOCK
# 
# @param:  	NONE
# @return: 	NONE
# @desc: 	Wait some random time and try to acquire the lock.
#--------------------------------------------------------------------------------
LOCK() {
	RANDON_WAIT
	(set -C; : > $LOCK_FILE) 2> /dev/null
	if [ $? != "0" ]; then
   		SYSLOG "Lock File exists - exiting"
   		exit 1
	fi
	
	SYSLOG "Lock File acquired!"
	trap 'rm $LOCK_FILE' EXIT
}


#--------------------------------------------------------------------------------
# @LDAPQUERY
# 
# @param: 	NONE
# @return:	Output files.	
# @desc:	Makes the ldap query in order to get entrustPolicyCertificate.
#--------------------------------------------------------------------------------
LDAPQUERY() {
${LDAPSEARCH} -1 -LLL -x -b "o=seg-social,c=es" -h ${LDAP_HOST} "ou=sgi" entrustPolicyCertificate  > ${TMP_BASE}
LDAP_EXCEPTION $?
${LDAPSEARCH} -1 -LLL -x -b "ou=sgi,o=seg-social,c=es" -h ${LDAP_HOST} "cn=end user policy" entrustPolicyCertificate  > ${TMP_EUSR}
LDAP_EXCEPTION $?
}

#--------------------------------------------------------------------------------
# @CLEANUP
# 
# @param: NONE
# @return
# @desc Deletes temporal files
#--------------------------------------------------------------------------------
CLEANUP() {
	${RM} ${TMP_BASE}
	${RM} ${TMP_EUSR}
	${FIND} ${SHARED_DIR} -name "${POLICY_NAME}.*" -mtime +${BACK_RETENTION} -exec ${RM} {} \;
}


#--------------------------------------------------------------------------------
# @PEM2PCH
# 
# @param: @1 CERTIFICATE. @2 LINE SIZE
# @return
# @desc 
#--------------------------------------------------------------------------------
PEM2PCH() {
	P1_PEM=$1
	P2_LEN=$2
	typeset -i counter
	counter=0
	while [ $counter -lt ${#P1_PEM} ] ; do
		if [ $counter -eq 0 ]; then 
			printf "PolicyCert=%s\r\n" "${P1_PEM:$counter:$P2_LEN}"
		else	
			printf "_continue_=%s\r\n" "${P1_PEM:$counter:$P2_LEN}"
		fi	
		counter=$counter+$P2_LEN
	done
}
	
#--------------------------------------------------------------------------------
# @LDIF2PCH
# 
# @param: 
# @return
# @desc Deletes temporal files
#--------------------------------------------------------------------------------
LDIF2PCH() {
	P1_PATTERN=$1
	P2_REPLACE=$2
	P3_FILE=$3
	
	CERTIFICATE=""
	while read -r m_line
	do 
		if [ ${#m_line} -eq 0 ]; then
			continue
		fi
		if [ "$m_line" = "$P1_PATTERN" ]; then
			printf "[$P2_REPLACE]\r\n"
			continue
		fi
		CERTIFICATE=${CERTIFICATE}$(printf "%s" "${m_line/entrustPolicyCertificate:: /}")
	done < ${P3_FILE} 
	PEM2PCH $CERTIFICATE $PCH_LINE_LEN
	printf "\r\n"
}


#--------------------------------------------------------------------------------
# MAIN PROC
#--------------------------------------------------------------------------------

LOCK

${FIND} ${SHARED_DIR} -name "${POLICY_NAME}" -mtime 0 | ${GREP} ${POLICY_EPCH}
if [ $? -eq 0 ]; then
	SYSLOG "POLICY FILE ALREADY UPDATED TODAY!"
	exit
fi

LDAPQUERY
LDIF2PCH "dn: ou=SGI,o=Seg-social,c=es" "ou=sgi,o=seg-social,c=es" $TMP_BASE > ${TMP_EPCH}
LDIF2PCH "dn: cn=End User Policy,ou=SGI,o=Seg-social,c=es" "cn=end user policy,ou=sgi,o=seg-social,c=es" $TMP_EUSR >> ${TMP_EPCH}

if [ -f ${POLICY_EPCH} ]
then
	${DIFF} ${POLICY_EPCH} ${TMP_EPCH}  > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		SYSLOG "POLICY FILE NOT CHANGED!"
		${RM} ${TMP_EPCH}
	else
		SYSLOG "POLICY FILE UPDATED!"
		BCK_SUFIX=$(${DATE} ${MSK_TIME})
		${MV} ${POLICY_EPCH} ${POLICY_EPCH}.${BCK_SUFIX}
		${MV} ${TMP_EPCH} ${POLICY_EPCH}	
		${CHOWN} ${USER}:${GROUP} ${POLICY_EPCH}
	fi		
else
	${MV} ${TMP_EPCH} ${POLICY_EPCH}
	${CHOWN} ${USER}:${GROUP} ${POLICY_EPCH}
fi

CLEANUP
