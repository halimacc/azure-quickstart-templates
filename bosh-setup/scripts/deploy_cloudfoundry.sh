#!/usr/bin/env bash

if [[ $# -ne 1 || -z "$1" ]]; then
    echo "Usage: ./deploy_cloudfoundry.sh <path-to-your-manifest>"
    exit 1
fi

set -e

manifest=$1
default_password="c1oudc0w"

while true; do
  read -p "Enter a password to use in $manifest [$default_password]:" password
  password=${password:-$default_password}
  read -p "Please double check your password [$password]. Type yes to continue:" ret
  if [ "$ret" == "yes" ]; then
    break
  fi
done

password=$(echo $password | sed 's/\//\\\//g')
password=${password:-$default_password}
sed -i "s/REPLACE_WITH_PASSWORD/$password/g" $manifest

bosh upload stemcell {{STEMCELL_URL}} --sha1 {{STEMCELL_SHA1}} --skip-if-exists
bosh upload release {{CF_RELEASE_URL}} --sha1 {{CF_RELEASE_SHA1}} --skip-if-exists
bosh upload release {{DIEGO_RELEASE_URL}} --sha1 {{DIEGO_RELEASE_SHA1}} --skip-if-exists
bosh upload release {{GARDEN_RELEASE_URL}} --sha1 {{GARDEN_RELEASE_SHA1}} --skip-if-exists
bosh upload release {{CFLINUXFS2_RELEASE_URL}} --sha1 {{CFLINUXFS2_RELEASE_SHA1}} --skip-if-exists

bosh deployment $manifest
bosh -n deploy
