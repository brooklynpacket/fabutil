import getpass
import re
import os
import socket
import tempfile

from datetime import datetime
from fabric.api import env
from fabric.api import run as fabric_run, sudo as fabric_sudo, local as fabric_local
from fabric.api import put as fabric_put, get as fabric_get, cd as fabric_cd
from fabric.decorators import task, runs_once, roles
from fabric.colors import red
from fabric.contrib.files import exists, append, contains
from fabric.context_managers import settings
try:
    import irclib
    irclib_loaded=True
except ImportError:
    print(red('fabutil2: irclib not found!'))
    irclib_loaded=False

def set_defaults():
    'Set default environment values.'
    env.deploy_user = getpass.getuser()
    env.deploy_hostname = socket.gethostname()
    env.format = True
    env.pypi = 'http://pypi.python.org/simple'
    env.python = 'python'
    env.virtualenv = 'virtualenv -p {python} --no-site-packages --distribute'.format(**env)
    env.now = datetime.now().strftime('%Y%m%d%H%M%S')
    try:
        env.gitrev = fabric_local('git describe --dirty --all --long',
                                    capture=True)
    except:
        env.gitrev = None
    else:
        env.gitrev = env.gitrev.replace('/', '-')
    env.base = '{now}-{gitrev}'.format(**env)


#
# Deployment Helpers
#


def u_h(u, h):
    return '@'.join((u, h))


def get_ec2_cluster(application_group, tagname='application-group'):
    import boto
    c = boto.connect_ec2()
    iids = [t.res_id for t in c.get_all_tags()
            if t.name == tagname and t.value == application_group]
    instances = [i.instances[0] for i in c.get_all_instances(instance_ids=iids)]
    return instances


def formatargs(func):
    def wrapper(*args, **kwargs):
        if getattr(env, 'format', False) is True:
            args = map(lambda x: x.format(**env) if isinstance(x, basestring) else x, args)
        return func(*args, **kwargs)
    return wrapper


def virtualenv(func):
    def wrapper(command, *args, **kwargs):
        if kwargs.pop('virtualenv', False) is True:
            activate = '{home}/releases/{base}/bin/activate'.format(**env)
            command = 'source "%s" && %s' % (activate, command)
        return func(command, *args, **kwargs)
    return wrapper


@virtualenv
@formatargs
def run(command, **kwargs):
    return fabric_run(command, **kwargs)


@virtualenv
@formatargs
def sudo(command, **kwargs):
    return fabric_sudo(command, **kwargs)


@formatargs
def local(command, **kwargs):
    return fabric_local(command, **kwargs)


@formatargs
def put(local_path, remote_path, **kwargs):
    formatted = None
    if 'putstr' in kwargs:
        formatted = kwargs.pop('putstr').format(**env)
    elif kwargs.pop('template', False) is True:
        with open(local_path) as file:
            formatted = file.read().format(**env)

    if formatted is not None:
        (fd, filename) = tempfile.mkstemp()
        with open(filename, 'w') as file:
            file.write(formatted)
            file.flush()
    else:
        filename = local_path
    return fabric_put(filename, remote_path, **kwargs)


@formatargs
def get(remote_path, local_path):
    return fabric_get(remote_path, local_path)


@formatargs
def cd(remote_path):
    return fabric_cd(remote_path)


@task
@runs_once
def print_hosts():
    """Print the list of targets for an environment."""
    for role, hosts in env.roledefs.items():
        print role + ':'
        for host in hosts:
            print '  ' + host


#
# Management Commands
#


@task
@roles('system-role')
def configure_nginx(conf, name):
    env.nginx_vhost_name = name
    env.python_version = run("""python -c 'import sys; print "python%d.%d" % (
            sys.version_info[0], sys.version_info[1])'""")
    put(conf, '/etc/nginx/sites-available/{nginx_vhost_name}',
        use_sudo=True, template=True)
    sudo('ln -sf /etc/nginx/sites-available/{nginx_vhost_name}'
         ' /etc/nginx/sites-enabled/{nginx_vhost_name}')
    sudo('/etc/init.d/nginx restart')


@task
@roles('system-role')
def configure_sd_plugin(conf):
    '''Copies a plugin template to a plugin directory, and points the ServerDensity config file at that directory'''
    if conf.endswith('.template'):
        filename = conf[:-9].split('/')[-1]
    else:
        filename = conf.split('/')[-1]
    sudo('mkdir -p /usr/bin/sd-agent/plugins')
    put(conf, '/usr/bin/sd-agent/plugins/'+filename, template=True, use_sudo=True)
    sudo('perl -pi -e "s/^plugin_directory:.*\$/plugin_directory: \/usr\/bin\/sd-agent\/plugins/" -f /etc/sd-agent/config.cfg', user="sd-agent")
    sudo('/etc/init.d/sd-agent restart')

@task
@roles('web')
def deploy_crontab():
    if env.crontab:
        put(None, '{home}/tmp/crontab', putstr=env.crontab + '\n\n')
        run('crontab {home}/tmp/crontab')


@task
@roles('web')
def sv(cmd, service):
    run('SVDIR={home}/service sv ' + cmd + ' ' + service)


#
# Utility functions
#

@task
@runs_once
def build_packages():
    '''Find setup.py files and run them.
    '''
    # --force-manifest is only available with distutils, not
    # setuptools/distribute.  Sigh.
    base = os.path.abspath('.')
    local('find {0} -name MANIFEST | xargs rm'.format(base))

    base_dirs = []
    dist_dir = os.path.abspath('./dist')
    local('mkdir -p {0}'.format(dist_dir))
    for root, dirs, files in os.walk('.'):
        if 'setup.py' in files:
            base_dirs.append(root)
    for rel_base in base_dirs:
        base = os.path.abspath(rel_base)
        base_dist = os.path.join(base, 'dist')
        local('cd {0} && python setup.py sdist'.format(base))
        if base_dist != dist_dir:
            local('mv {0}/* {1}'.format(base_dist, dist_dir))
            local('rmdir {0}'.format(base_dist))


def sshagent_run(cmd):
    """
    Helper function.
    Runs a command with SSH agent forwarding enabled.

    Note:: Fabric (and paramiko) can't forward your SSH agent.
    This helper uses your system's ssh to do so.
    """

    if env.get('forward_agent', False):
        return run(cmd)

    h = env.host_string
    try:
        # catch the port number to pass to ssh
        host, port = h.split(':')
        return local('ssh -p %s -A %s "%s"' % (port, host, cmd))
    except ValueError:
        return local('ssh -A %s "%s"' % (h, cmd))


#
# Admin Setup
#


def _setup_system_role_env(acct, home):
    if acct is not None:
        env.acct = acct
    if home is not None:
        env.home = home
    if 'home' not in env:
        env.home = '/srv/' + env.acct


@task
@roles('system-role')
def setup_base_system(acct=None, home=None):
    _setup_system_role_env(acct, home)
    hostname = run('hostname')
    if not contains('/etc/hosts', hostname):
        sudo('echo 127.0.0.1 %s >> /etc/hosts' % hostname)
    packages = ['gcc', 'make', 'nginx', 'python-virtualenv', 'runit',
                'subversion', 'python-dev', 'libevent-dev',
                'postfix', 'memcached', 'openssl', 'libssl-dev']
    sudo('DEBIAN_FRONTEND=noninteractive apt-get -q -y install ' + ' '.join(packages))
    for package in ('git', 'git-core'):
        with settings(warn_only=True):
            sudo('apt-get -q -y install ' + package)
    if not exists('/srv') or not str(run('ls /srv')):
        sudo('rm -rf /srv')
        sudo('ln -s /mnt /srv')


@task
@roles('system-role')
def setup_user(acct=None, home=None):
    _setup_system_role_env(acct, home)
    setup_user_account(acct, home)
    setup_user_runit(acct, home)


@task
@roles('system-role')
def setup_user_account(acct=None, home=None):
    _setup_system_role_env(acct, home)
    sudo('yes "\n" | adduser --shell /bin/bash '
         '--quiet --disabled-password --home {home} {acct}')
    sudo('mkdir -m 700 -p {home}/.ssh')
    # We use $HOME/.ssh/authorized_keys2 for keys managed with this approach.
    if 'authorized_keys' in env:
        auth2 = ('# DO NOT EDIT, MANAGED BY fabfile.py\n' + 
                 '\n'.join(env.authorized_keys))
        put(None, '{home}/.ssh/authorized_keys2',
            putstr=auth2, use_sudo=True)
        sudo('chmod 600 {home}/.ssh/authorized_keys2')
    sudo('chown -R {acct}:{acct} {home}')
    sudo('adduser {acct} adm')


@task
@roles('system-role')
def setup_user_runit(acct=None, home=None):
    _setup_system_role_env(acct, home)
    env.runit_log_dir = '{home}/shared/log/runit'.format(**env)
    runfile = ('#!/bin/sh\n'
               'exec 2>&1\n'
               'exec chpst -u{acct} runsvdir {home}/service\n').format(**env)

    runfile_log = ('#!/bin/sh\n'
                   'exec chpst -u{acct} svlogd -tt {runit_log_dir}/\n')
    
    sudo('mkdir -p {runit_log_dir}')
    sudo('mkdir -p {home}/{{shared,service}}')
    sudo('chown -R {acct}:{acct} {home}')
        
    sudo('mkdir -p /etc/service/{acct}/log')
    sudo('mkdir -p /etc/sv/{acct}')
    sudo('ln -sf /etc/service/{acct}/run /etc/sv/{acct}/run')
    sudo('ln -sf /etc/service/{acct}/log /etc/sv/{acct}/log')
    # template=True implied by use of putstr argument.
    put(None, '/etc/service/{acct}/run', putstr=runfile, use_sudo=True)
    put(None, '/etc/service/{acct}/log/run', putstr=runfile_log, use_sudo=True)
    sudo('chown root:root /etc/service/{acct}/run')
    sudo('chown root:root /etc/service/{acct}/log/run')
    sudo('chmod 755 /etc/service/{acct}/run')
    sudo('chmod 755 /etc/service/{acct}/log/run')


#
# Local redis setup.
#


@task
@roles('web')
def install_redis(conf='etc/redis.conf.template',
                  src='http://redis.googlecode.com/files/redis-2.2.12.tar.gz'):
    run('mkdir -p {home}/redis/etc/redis')
    run('mkdir -p {home}/redis/src')
    put(conf, '{home}/redis/etc/redis/redis.conf', template=True)
    redis_distro = os.path.basename(src)
    for ext, topts in (
            ('.tar', 'xf'),
            ('.tar.gz', 'zxf'),
            ('.tgz', 'zxf'),
            ('.tar.bz2', 'jxf'),
            ('.tbz2', 'jxf')):
        if redis_distro.endswith(ext):
            redis_src_dir = redis_distro.rstrip(ext)
            untar_opts = topts
            break

    with cd(os.path.join(env.home, 'redis', 'src')):
        run('wget -c "%s"' % src)
        run(' '.join(('tar', untar_opts, redis_distro)))

    with cd(os.path.join(env.home, 'redis', 'src', redis_src_dir)):
        run("sed '133 s/$/ -lm/' --in-place src/Makefile")
        run('make')
        run('make PREFIX={home}/redis/ install' % env)

    redis_runit_template = (
        '#!/bin/bash\n\n'
        'REDIS={home}/redis/bin/redis-server\n'
        'CONF={home}/redis/etc/redis/redis.conf\n'
        'PID={home}/shared/run/redis.pid\n'
        'if [ -f $PID ]; then rm $PID; fi\n'
        'exec $REDIS $CONF\n')

    run('mkdir -p {home}/service/redis')
    put(None, '{home}/service/redis/run', putstr=redis_runit_template)
    run('chmod 755 {home}/service/redis/run')


@task
@roles('web')
def start_redis():
    'Start Redis database'
    run('SVDIR={home}/service sv start redis')


@task
@roles('web')
def kill_redis():
    'Stop Redis database'
    run('SVDIR={home}/service sv stop redis')

import time

def irc_msg(server, port, nick, channel, msg, password=None, sleep=5):
    if irclib_loaded:
        client = irclib.SimpleIRCClient()
        if password is not None:
            client.connect(server, port, nick, password=password)
        else:
            client.connect(server, port, nick)
        time.sleep(sleep)
        client.connection.join(channel)
        time.sleep(sleep)
        client.connection.privmsg(channel, msg)
        client.connection.close()
    else:
        pass

@task
@roles('system-role')
def delete_mail_queue():
    'Delete postfix email queue'
    sudo('postsuper -d ALL')


def pre_deploy_check(directories=['.'],
                     notes_files=set(['deploy_notes.txt', 'deploy_notes']),
                     done_files=set(['deploy_done.txt', 'deploy_done'])):
    '''Check for deployment tasks that have not been done.

    It walks down from the specified directories, tries to find all
    ``deploy_notes.txt`` and aggregates all deployment tasks. Then it does the
    same to ``deploy_done.txt``. In the end, it compares the results together.
    If there is any entry in ``deploy_notes`` that is not in ``deploy_done``,
    it raises an :class:`EnvironmentError`.

    Args:

        directories (sequence of string): list of directories to recursively
            dive in to find ``deploy_notes`` and ``deploy_done``
        notes_files (collection of string): a set of file names that will be
            considered ``deploy_notes`` files
        done_files (collection of string): a set of file names that will be
            considered ``deploy_done`` files

    Raises:

        EnvironmentError: if any entry in ``deploy_notes`` is not found
            in ``deploy_done``

    '''

    def find_notes_and_done(directory, notes_files, done_files):
        notes = set()
        done = set()
        # match at least 32 0-9a-f after (optional) commit, in a line
        pattern = re.compile('^(commit )?([0-9a-fA-F]{32,})$')
        for root, dirs, files in os.walk(directory):
            for name in files:
                if name in notes_files:
                    var = notes
                elif name in done_files:
                    var = done
                else:
                    continue
                name = os.path.join(root, name)
                with open(name, 'rb') as inp:
                    for line in inp:
                        line = line.strip()
                        matches = pattern.match(line)
                        if matches:
                            commit_id = matches.group(2)
                            var.add(commit_id)

        return notes, done

    all_notes = set()
    all_done = set()
    for d in directories:
        notes, done = find_notes_and_done(d, notes_files, done_files)
        all_notes.update(notes)
        all_done.update(done)

    undone = all_notes - all_done
    if undone:
        raise EnvironmentError (
                'There are undone pre-deployment tasks:\n\t' +
                '\t'.join(undone))


def origin_check():
    '''Check if all commits are pushed out to origin/master.

    Raises:

        EnvironmentError: if either local branch is not ``master`` or it does
            not point to the same commit as ``origin/master``

    '''

    # are we on master?
    branch = ''
    with settings(warn_only=True):
        branch = local('git branch --no-color | grep "\* master"',
                       capture=True).strip()
    if not branch:
        raise EnvironmentError('Local repository is not on master branch.')

    # origin/master and master point to the same commit?
    origin_latest = local('git log --no-color origin/master -1')
    local_latest = local('git log --no-color master -1')
    if origin_latest != local_latest:
        raise EnvironmentError('Local repository is different from origin.')


def lock_check():
    '''Check if other deployment has not completed cleanly.

    It does this by looking at the last line of ``.fablog``. In case a previous
    deployment was terminated abruptly, this function would still raise error.

    Raises:

        EnvironmentError: if another deployment has not completed cleanly

    '''

    last_line = ''
    with settings(warn_only=True):
        last_line = run('tail -n 1 .fablog')
    if not (last_line.endswith(' ERROR.') or last_line.endswith(' DONE.')):
        raise EnvironmentError(
            'Previous deployment did not complete cleanly.\n\t' + last_line)


@task
@roles('web')
def update_package_repository(pip='CURRENT/bin/pip',
                              cache_directory='{home}/shared/pipdcache/',
                              requirements_file='{home}/tmp/requirements.txt'):
    '''Update local repository cache.

    Latest packages from PyPI will be downloaded to $HOME/shared/pipdcache.

    We will use this cache to install packages in :func:`deploy_bootstrap`.

    We use ``CURRENT/bin/pip`` instead of ``/usr/bin/pip`` because the default
    ``pip`` in Ubuntu is too old to support ``--download``.
    '''

    install_req = ' '.join([pip, 'install', '--download', cache_directory,
                            '--no-install', '--exists-action', 'w', '-r',
                            requirements_file]).format(**env)
    # we need SSH forwarding here because some packages are checked out from
    # private Github repository
    sshagent_run(install_req)

    # update timestamp
    # we copy the requirements file here so that we can check if requirements
    # have been changed later, in is_repository_out_of_date
    run('cp --no-preserve=timestamps ' + requirements_file + ' ' +
            cache_directory + '/.timestamp')


def install_from_package_repository(pip='CURRENT/bin/pip',
                            cache_directory='file://{home}/shared/pipdcache',
                            requirements_file='{home}/tmp/requirements2.txt'):
    run(' '.join([pip, 'install', '--no-index', '--quiet', '--find-links',
                  cache_directory, '-r', requirements_file]).format(**env))


def is_repository_out_of_date(cache_directory='{home}/shared/pipdcache/',
                              days=15, requirements_file=None):

    timestamp_file = cache_directory + '/.timestamp'

    # get timestamp of the cache directory
    with settings(warn_only=True):
        last_update = run('stat -c %Y ' + timestamp_file + ' 2>/dev/null')
        # this is not a real string, we need to convert it to string
        last_update = str(last_update)
    try:
        last_update = int(last_update)
    except ValueError:
        last_update = 0

    # has it been days?
    now = int(time.time())
    if now - last_update >= 86400 * days:
        return True

    if not requirements_file:
        return False

    # check content
    try:
        run('diff ' + requirements_file + ' ' + timestamp_file) 
        # exit code = 0, no diff
    except:
        # requirements have been changed, cache is out of date
        return True

    return False


@task
@roles('web')
def clone_mysql(source_host, source_user, source_pass, source_db,
            dest_host, dest_user, dest_pass, dest_db):
    # the network diagram is like this
    #
    # dest_mysql <---> localhost <---> source_mysql
    #
    # dest_mysql might not be connectable to source_mysql
    # and dest_mysql might only be listening on 127.0.0.1
    #
    # so the best way is to dump source_mysql to a local file
    # upload that file to dest_mysql
    # then restore the dump

    with settings(warn_only=True):
        for executable in ('mysql5', 'mysql'):
            if str(run('which ' + executable)):
                mysql_bin = executable
        for executable in ('mysqldump5', 'mysqldump'):
            if str(local('which ' + executable, capture=True)):
                mysqldump_bin = executable
    try:
        local(' '.join([mysqldump_bin, '--add-drop-table', '--compress',
                '--host', source_host, '--user', source_user,
                '--password=' + source_pass, source_db,
                '>',
                '/tmp/__fab_mysql_dump.sql']))
        try:
            put('/tmp/__fab_mysql_dump.sql', '/tmp/__fab_mysql_dump2.sql')
            run(' '.join([mysql_bin, '--host', dest_host, '--user', dest_user,
                    '--password=' + dest_pass, dest_db,
                    '<',
                    '/tmp/__fab_mysql_dump2.sql']))
        finally:
            run('rm -rf /tmp/__fab_mysql_dump2.sql')
    finally:
        local('rm -rf /tmp/__fab_mysql_dump.sql')


def __get_db_conf(conf_file, profile):
    global_dict = {}
    local_dict = {}
    execfile(conf_file, global_dict, local_dict)
    dbconf = local_dict['DATABASES'][profile]
    return dbconf


@task
@roles('system-role')
def setup_mysql():
    with settings(warn_only=True):
        sudo('DEBIAN_FRONTEND=noninteractive apt-get -q -y '
             'install mysql-server')
    db_conf = __get_db_conf(env.overrides, 'default')
    user = db_conf['USER']
    password = db_conf['PASSWORD']
    db = db_conf['NAME']
    run('echo "'
        'grant usage on *.* to %s@\'%%\'; drop user %s@\'%%\'; '
        'create user \'%s\'@\'%%\' identified by \'%s\'; '
        'grant usage on *.* to %s@\'localhost\'; drop user %s@\'localhost\'; '
        'create user \'%s\'@\'localhost\' identified by \'%s\'; '
        'drop database if exists %s; '
        'create database %s default charset \'utf8\'; '
        'grant all on %s.* to %s;" | mysql -u root mysql' % (
                        user, user, user, password,
                        user, user, user, password,
                        db, db, db, user))


@task
@roles('web')
def clone_from_config(source, dest):
    source_conf = __get_db_conf(source, 'default')
    source_db = source_conf['NAME']
    source_host = source_conf['HOST']
    source_user = source_conf['USER']
    source_pass = source_conf['PASSWORD']
    dest_conf = __get_db_conf(dest, 'default')
    dest_db = dest_conf['NAME']
    dest_host = dest_conf['HOST']
    dest_user = dest_conf['USER']
    dest_pass = dest_conf['PASSWORD']
    clone_mysql(source_host, source_user, source_pass, source_db,
            dest_host, dest_user, dest_pass, dest_db)
