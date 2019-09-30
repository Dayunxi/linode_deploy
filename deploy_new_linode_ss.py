from ssh2.session import Session
import socket
import time
import re
import requests
from configparser import ConfigParser
import json


def load_config(ini_path):
    config = ConfigParser(allow_no_value=True)
    config.read(ini_path)
    return config


def get_linode_type_list():
    request_url = 'https://api.linode.com/v4/linode/types'
    rsp = requests.get(request_url)
    return json.loads(rsp.text)


def get_linode_region_list():
    request_url = 'https://api.linode.com/v4/regions'
    rsp = requests.get(request_url)
    return json.loads(rsp.text)


def get_linode_image_list():
    request_url = 'https://api.linode.com/v4/images'
    rsp = requests.get(request_url)
    return json.loads(rsp.text)


def query_linodes_info():
    types = get_linode_type_list()
    print(types)
    regions = get_linode_region_list()
    print(regions)
    images = get_linode_image_list()
    print(images)


def request_create_linode(config):
    request_url = 'https://api.linode.com/v4/linode/instances'
    header = {"Authorization": "Bearer {}".format(config['access_token']),
              "Content-type": "application/json"
              }
    data = {"type": config['type'],
            "region": config['region'],
            "image": config['image'],
            "root_pass": config['root_pass'],
            "label": config['label']
            }
    rsp = requests.post(request_url, headers=header, data=json.dumps(data))
    return json.loads(rsp.text)


def request_delete_linode(token, instance_id):
    request_url = 'https://api.linode.com/v4/linode/instances/{}'.format(instance_id)
    header = {"Authorization": "Bearer {}".format(token)}
    rsp = requests.delete(request_url, headers=header)
    return json.loads(rsp.text)


def get_all_instances(token):
    request_url = 'https://api.linode.com/v4/linode/instances'
    header = {"Authorization": "Bearer {}".format(token)}
    rsp = requests.get(request_url, headers=header)
    return json.loads(rsp.text)


def get_instance_state(token, instance_id):
    request_url = 'https://api.linode.com/v4/linode/instances/{}'.format(instance_id)
    header = {"Authorization": "Bearer {}".format(token)}
    rsp = requests.get(request_url, headers=header)
    return json.loads(rsp.text)


def create_new_linode(config):
    print('[*]New instance\'s configuration:')
    for item in config.items():
        print("\t{} = {}".format(item[0], item[1]))
    if input('[*]Continue or not? (y/n):') != 'y':
        return
    new_instance_info = request_create_linode(config)
    if 'errors' in new_instance_info.keys():
        print(new_instance_info)
        return None
    while new_instance_info['status'] != 'running':
        print('[*]Server status: {} ...'.format(new_instance_info['status']))
        time.sleep(2)
        new_instance_info = get_instance_state(config['access_token'], new_instance_info['id'])
    return new_instance_info


def delete_old_linode(token, instance):
    print('[*]Delete old instance id: {} label: {} ...'.format(instance['id'], instance['label']))
    if input('Continue or not? (y/n):') != 'y':
        return
    rsp = request_delete_linode(token, instance['id'])
    if rsp != {}:
        print('[-]Fail to delete instance {}, rsp:'.format(instance['label']), rsp)
    else:
        print('[+]Delete {} success'.format(instance['label']))


def linode_part(config):
    skip_create = False
    skip_delete = False
    old_instance = {}
    new_instance = {}

    # query_linodes_info()
    print('[+]Get all instances\'s info ...')
    instances = get_all_instances(config['access_token'])
    if instances['results'] >= 1:
        print("[+]Please choose an instance to replace")
        for index, instance in enumerate(instances['data']):
            print('[*]Index:', index, instance)
        index = input('Index of instance: ')
        old_instance = instances['data'][int(index)]
    # elif instances['results'] == 1:
    #     old_instance = instances['data'][0]
    else:
        print('[-]You have no instance or request error')
        skip_delete = True

    # delete old linode
    if not skip_delete:
        delete_old_linode(config['access_token'], old_instance)
    else:
        print('[*]Skip delete')

    # check redundant or not
    for instance in instances['data']:
        if config['label'] == instance['label']:
            print('[*]Label {} is already exist'.format(config['label']))
            delete_old_linode(config['access_token'], old_instance)
            skip_delete = True

    # create new linode
    if not skip_create:
        new_instance = create_new_linode(config)
        print(new_instance)
        if not new_instance:
            print('[-]Fail to create instance')
            skip_delete = True
    else:
        print('[*]Skip create')


    if not new_instance:
        print('[-]Create instance fail')
        exit(0)

    login_info = {'ip': {'v4': new_instance['ipv4'][0], 'v6': new_instance['ipv6'].split('/')[0]},
                  'username': 'root',
                  'password': config['root_pass']}
    return login_info


def ssh_login(ip, username, password):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    is_ipv4_timeout = False
    is_ipv6_timeout = False
    while True:
        try:
            if not is_ipv4_timeout:
                print('[+]Try to connect to {}:22'.format(ip['v4']))
                sock.connect((ip['v4'], 22))
            elif not is_ipv6_timeout:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                print('[+]Try to connect to {}:22'.format(ip['v6']))
                sock.connect((ip['v6'], 22))
            else:
                print('[-]Cannot connect to host, rerun this script and try again')
                exit(0)
            break
        except TimeoutError as ex:
            print(ex)
            if not is_ipv4_timeout:
                is_ipv4_timeout = True
            elif not is_ipv6_timeout:
                is_ipv6_timeout = True
        except ConnectionRefusedError as ex:
            print(ex)
            print('[+] Sleep 5s and then retry ...')
            time.sleep(5)
    print('[+]Connect success')
    session = Session()
    session.handshake(sock)
    session.userauth_password(username, password)

    return session


def ssh_execute(session, cmd):
    print('[*]Command:', cmd)
    channel = session.open_session()
    channel.execute(cmd)
    stdout = ''
    stderr = ''
    while True:
        size, tmp = channel.read()
        if size <= 0:
            break
        tmp = str(tmp, encoding='utf-8')
        stdout += tmp
        print(tmp, end='')
        if re.search('(yes/no|y/n)', stdout[-20:], flags=re.IGNORECASE):
            rsp = input()
            channel.write(rsp + '\r\n')

    while True:
        size, tmp = channel.read_stderr()
        if size <= 0:
            break
        tmp = str(tmp, encoding='utf-8')
        stderr += tmp
        print(tmp, end='')
    # channel.close()
    return stdout, stderr


# use bbr
def set_bbr(session, congestion):
    if congestion != 'bbr':
        return
    # check version
    required_version = '4.9'
    required_version = [int(item) for item in required_version.split('.')]
    kernel_version, _ = ssh_execute(session, 'uname -r')
    kernel_version = kernel_version.split('-')[0].split('.')
    kernel_version = [int(item) for item in kernel_version]
    if kernel_version < required_version:
        print('[-] Your kernel version is lower than 4.9, please update')
        exit(0)

    cmd = 'echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" >> /etc/sysctl.conf'
    ssh_execute(session, cmd)
    ssh_execute(session, 'sysctl -p')
    stdout, stderr = ssh_execute(session, 'sysctl net.ipv4.tcp_congestion_control')
    if 'bbr' not in stdout:
        print('[-]Set bbr error')
        exit(0)


# default: Unbuntu
def setup_shadowsocks_env(session):
    # install
    ssh_execute(session, 'apt-get update')
    ssh_execute(session, 'apt-get install python-pip')
    ssh_execute(session, 'pip install shadowsocks')
    # modify openssl.py
    py_path = '/usr/local/lib/python2.7/dist-packages/shadowsocks/crypto/openssl.py'
    cmd = 'sed -i "s/_cleanup/_reset/g" {}'.format(py_path)
    ssh_execute(session, cmd)


def run_shadowsocks(session, config):
    # configure
    ss_config = {"server": "::",
                 "server_port": config['port'],
                 "local_address": "127.0.0.1",
                 "local_port": 1080,
                 "password": config['port_passwd'],
                 "timeout": 300,
                 "method": config['encrypt'],
                 "fast_open": False}
    json_str = json.dumps(ss_config, indent=4)
    json_str = json_str.replace('"', '\\"')
    cmd = 'echo -e "{}" > /etc/shadowsocks.json'.format(json_str)
    ssh_execute(session, cmd)
    # start
    ssh_execute(session, 'ssserver -c /etc/shadowsocks.json -d start')


def server_part(info, config, congestion='bbr'):
    print(info)
    session = ssh_login(info['ip'], info['username'], info['password'])
    set_bbr(session, congestion)
    setup_shadowsocks_env(session)
    run_shadowsocks(session, config)
    return session


def menu():
    print('[+]Please switch the next step')
    print('1. delete linode instance')
    print('2. create linode instance')
    print('3. deploy shadowsocks service')
    pass


def main():
    config = load_config('deploy_config.ini')
    # login_info = linode_part(config['Linode'])
    # for i in range(5, 0, -1):
    #     print('[*]Wait for {}s ...'.format(i))
    #     time.sleep(1)
    login_info = {'ip': {'v4': '173.255.250.11', 'v6': ''},
                  'username': 'root',
                  'password': config['Linode']['root_pass']}
    server_part(login_info, config['Shadowsocks'], congestion=config['Server']['congestion'])


if __name__ == '__main__':
    main()

