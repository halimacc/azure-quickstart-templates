#!/usr/bin/env python

import os
import sys
import json
import re

from subprocess import call
from subprocess import check_output
from shutil import copy
from shutil import move


def install_packages(settings):
    import apt
    from time import sleep

    print "Start to install prerequisite packages..."

    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'

    # moved packages needed for bosh_cli here
    packages = [
        'python-pip',
        'build-essential',
        'ruby2.0',
        'ruby2.0-dev',
        'libxml2-dev',
        'libsqlite3-dev',
        'libxslt1-dev',
        'libpq-dev',
        'libmysqlclient-dev',
        'zlibc',
        'zlib1g-dev',
        'openssl',
        'libssl-dev',
        'libreadline6',
        'libreadline6-dev',
        'libyaml-dev',
        'sqlite3',
        'libffi-dev'
    ]

    max_retries = 10
    retry_interval = 30

    for attempt in range(max_retries):
        try:
            cache = apt.Cache()
            cache.update(raise_on_error=False)
            cache.open(None)

            for package in packages:
                pkg = cache[package]
                if not pkg.is_installed:
                    pkg.mark_install(auto_inst=True)

            cache.commit()
            return
        except Exception as arg:
            print "Attempt #{0} failed, [{1}]".format(str(attempt), str(arg))
            sleep(retry_interval)

    print "Failed to install prerequisite packages"


def install_python_packages(settings):
    import pip

    print "Start to install python packages..."

    packages = ['jinja2', 'azure==2.0.0rc1', 'azure-storage', 'netaddr']

    params = ['install']
    if settings['ENVIRONMENT'] == 'AzureChinaCloud':
        params = params + ['--index-url', 'https://pypi.mirrors.ustc.edu.cn/simple/', '--default-timeout=60']

    # do not retry due to bug with pip.main
    for pkg in packages:
        if pip.main(params + [pkg]) != 0:
            print "Failed to install python package {0}".format(pkg)


def create_certs(settings):
    print "Start to generate SSH key pair for BOSH..."

    username = settings['ADMIN_USER_NAME']
    home_dir = os.path.join("/home", username)
    settings['HOME_DIR'] = home_dir

    bosh_key = 'bosh'
    call("ssh-keygen -t rsa -f {0} -P '' -C ''".format(bosh_key), shell=True)
    call("chmod 400 {0}".format(bosh_key), shell=True)
    copy(bosh_key, home_dir)
    copy(bosh_key + '.pub', home_dir)

    print "Start to generate SSL certificate for cloud foundry..."

    cf_key = 'cloudfoundry.key'
    cf_cert = 'cloudfoundry.cert'
    call("openssl genrsa -out {key} 2048 >/dev/null 2>&1".format(key=cf_key), shell=True)
    call("openssl req -new -x509 -days 365 -key {key} -out {cert} -subj \"/C=AU/ST=ZJU/L=ZHCN/O=Linux/OU=Soft/CN=test@abc.com\" >/dev/null 2>&1".format(key=cf_key, cert=cf_cert), shell=True)
    copy(cf_key, home_dir)
    copy(cf_cert, home_dir)


def prepare_storage(settings):
    from azure.storage.blob import AppendBlobService
    from azure.storage.table import TableService

    print "Start to prepare storage..."

    default_storage_account_name = settings["DEFAULT_STORAGE_ACCOUNT_NAME"]
    storage_access_key = settings["STORAGE_ACCESS_KEY"]
    endpoint_suffix = settings["SERVICE_HOST_BASE"]

    blob_service = AppendBlobService(account_name=default_storage_account_name, account_key=storage_access_key, endpoint_suffix=endpoint_suffix)
    blob_service.create_container('bosh')
    blob_service.create_container(
        container_name='stemcell',
        public_access='blob'
    )

    # Prepare the table for storing meta datas of storage account and stemcells
    table_service = TableService(account_name=default_storage_account_name, account_key=storage_access_key, endpoint_suffix=endpoint_suffix)
    table_service.create_table('stemcells')


def password(key):
    global pwdbook

    if not key in pwdbook:
        pwdbook[key] = check_output("openssl rand -base64 16 | tr -dc 'a-zA-Z0-9'", shell=True)

    return pwdbook[key]


def iprange(offset, addr_range):
    import netaddr

    ip = netaddr.IPNetwork(addr_range)
    return str(ip[int(offset)])


def render_manifests_and_commands(settings):
    from jinja2 import Environment
    global pwdbook
    pwdbook = {}

    jinja = Environment()
    jinja.filters['password'] = password
    jinja.filters['iprange'] = iprange

    environment = settings['ENVIRONMENT']

    print "Start to render manifests and deploy commands..."

    # prepare bosh settings
    with open('bosh.pub', 'r') as tmpfile:
        settings['SSH_PUBLIC_KEY'] = tmpfile.read()

    ntp_servers_maps = {
        'AzureCloud': '0.north-america.pool.ntp.org',
        'AzureChinaCloud': '1.cn.pool.ntp.org, 1.asia.pool.ntp.org, 0.asia.pool.ntp.org'
    }
    settings['NTP_SERVERS'] = ntp_servers_maps[environment]

    settings['ADMIN_PASSWORD'] = password('admin')
    settings['BOSH_DIRECTOR_IP'] = iprange(4, settings['SUBNET_ADDRESS_RANGE_FOR_BOSH'])

    # prepare cloud foundry settings
    dns_maps = {
        'AzureCloud': "168.63.129.16, {0}".format(settings["SECONDARY_DNS"]),
        'AzureChinaCloud': settings['BOSH_DIRECTOR_IP']
    }
    settings['DNS'] = dns_maps[environment]

    with open('cloudfoundry.cert', 'r') as tmpfile:
        ssl_cert = tmpfile.read()
    with open('cloudfoundry.key', 'r') as tmpfile:
        ssl_key = tmpfile.read()
    ssl_cert_and_key = "{0}{1}".format(ssl_cert, ssl_key)
    indentation = ' ' * 8
    ssl_cert_and_key = ('\n' + indentation).join([line for line in ssl_cert_and_key.split('\n')])
    settings['SSL_CERT_AND_KEY'] = ssl_cert_and_key

    # start rendering
    bosh_template = 'bosh.yml'
    bosh_deployment_command = 'deploy_bosh.sh'
    cloudfoundry_templates = ['single-vm-cf.yml', 'multiple-vm-cf.yml']
    cloudfoundry_deployment_cmd = 'deploy_cloudfoundry.sh'

    files_to_render = [bosh_template, bosh_deployment_command, cloudfoundry_deployment_cmd] + cloudfoundry_templates
    for filename in files_to_render:
        if os.path.exists(filename):
            with open(filename, 'r') as tmpfile:
                contents = tmpfile.read()
                contents = jinja.from_string(contents).render(settings)

            with open(filename, 'w') as tmpfile:
                tmpfile.write(contents)

    # move file home
    home_dir = settings['HOME_DIR']
    admin_password = settings['ADMIN_PASSWORD']

    copy(bosh_template, home_dir)
    call("chmod +x {0}".format(bosh_deployment_command), shell=True)
    copy(bosh_deployment_command, home_dir)
    call("echo {admin_password} > {home_dir}/BOSH_DIRECTOR_ADMIN_PASSWORD".format(admin_password=admin_password, home_dir=home_dir), shell=True)

    example_manifests = "{0}/example_manifests".format(home_dir)
    os.makedirs(example_manifests)
    copy('single-vm-cf.yml', example_manifests)
    copy('multiple-vm-cf.yml', example_manifests)
    call("chmod +x {0}".format(cloudfoundry_deployment_cmd), shell=True)
    copy(cloudfoundry_deployment_cmd, home_dir)


def install_bosh_cli_and_bosh_init(settings):
    # use ruby 2.0
    binary_dir = '/usr/bin'
    binaries = ['ruby', 'gem', 'irb', 'rdoc', 'erb']
    for binary in binaries:
        binary_path = os.path.join(binary_dir, binary)
        os.remove(binary_path)
        os.symlink(os.path.join(binary_dir, binary + '2.0'), binary_path)

    environment = settings['ENVIRONMENT']
    if (environment == 'AzureChinaCloud'):
        call("gem sources --remove https://rubygems.org/", shell=True)
        call("gem sources --add https://ruby.taobao.org/", shell=True)
        call("gem sources --add https://gems.ruby-china.org/", shell=True)

    call("gem sources -l", shell=True)
    call("gem update --system", shell=True)
    call("gem pristine --all", shell=True)

    print "Start to install bosh-cli..."

    call("gem install bosh_cli -v 1.3169.0 --no-ri --no-rdoc", shell=True)

    print "Start to install bosh-init..."

    bosh_init_url = settings['BOSH_INIT_URL']
    bosh_binary_path = '/usr/local/bin/bosh-init'

    call("wget -O {0} {1}".format(bosh_binary_path, bosh_init_url), shell=True)
    call("chmod +x {0}".format(bosh_binary_path), shell=True)


def deploy_bosh(settings):
    auto_deploy_bosh = settings['AUTO_DEPLOY_BOSH']
    username = settings['ADMIN_USER_NAME']
    home_dir = settings['HOME_DIR']

    call("chown -R {0} {1}".format(username, home_dir), shell=True)

    if auto_deploy_bosh != 'enabled':
        print "Finish"
        return

    print "Start to deploy bosh..."

    call("su -c ./deploy_bosh.sh - {0}".format(username), shell=True)


def get_settings():
    settings = dict()
    config_file = "/var/lib/cloud/instance/user-data.txt"
    with open(config_file) as f:
        settings = json.load(f)
    settings['TENANT_ID'] = sys.argv[1]
    settings['CLIENT_ID'] = sys.argv[2]
    settings['CLIENT_SECRET'] = sys.argv[3]

    return settings


def main():
    settings = get_settings()

    install_packages(settings)

    install_python_packages(settings)

    create_certs(settings)

    prepare_storage(settings)

    render_manifests_and_commands(settings)

    install_bosh_cli_and_bosh_init(settings)

    deploy_bosh(settings)

    # write settings for backward compatibility
    settings['cf-ip'] = settings['CLOUD_FOUNDRY_PUBLIC_IP']
    home_dir = settings['HOME_DIR']
    with open("{0}/settings".format(home_dir), "w") as tmpfile:
        tmpfile.write(json.dumps(settings, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
