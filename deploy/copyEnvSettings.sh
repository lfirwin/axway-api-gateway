#!/bin/bash

# Check for script arguments
if [ -z "$1" ]
then
   echo "Error: Missing command line options."
   exit 1
fi

# Get the target environment
if [ $# -ge 1 ]
then
   ENV=${1}
fi

# Get the action to perform
if [ $# -eq 2 ]
then
   ACTION=${2}
fi

# Set the script directory and the working directory
scriptdir=$(dirname $0)
if [ "$scriptdir" = "." ]
then
   scriptdir=$(pwd)
fi

if [ ! -f "${scriptdir}/environments/$ENV/${ENV}.props" ]
then
   echo "Error: ${scriptdir}/environments/$ENV/${ENV}.props is not found"
   exit 1
fi

. "${scriptdir}/environments/$ENV/${ENV}.props"

cd ${scriptdir}/environments/$ENV

echo "Creating envSettings.props file for $INSTANCE..."
cat "$INSTANCE" > /tmp/envSettings.props
if [ -f ${scriptdir}/environments/$ENV/envVariables.props ]
then
   cat ${scriptdir}/environments/$ENV/envVariables.props >> /tmp/envSettings.props
fi

for HOST in ${HOSTS[@]}
do
   echo "Backing up envSettings.props on $HOST..."
   ssh wasadm@$HOST "cp ${INSTALL_PATH}/instances/${INSTANCE}/conf/envSettings.props ${INSTALL_PATH}/instances/${INSTANCE}/conf/envSettings.props-bak"

   echo "Copying envSettings.props to $HOST..."
   scp /tmp/envSettings.props wasadm@$HOST:${INSTALL_PATH}/instances/${INSTANCE}/conf/envSettings.props

#     if [ -n "${ACTION}" ]
#     then
#       ssh wasadm@$HOST "cd ${SCRIPTS_DIR};./stop-${SCRIPT_DESIGNATOR}.sh;./start-${SCRIPT_DESIGNATOR}.sh"
#     fi
done

rm -f /tmp/envSettings.props

