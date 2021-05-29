#!/bin/bash
export KIEBITZ_SETTINGS=`readlink -f /srv/backend/settings/${environment}/`
echo -e "Starting Service ${service} in Environment: ${environment}"
`which kiebitz` run "${service}"
