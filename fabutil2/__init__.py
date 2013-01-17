import getpass
import re
import os
import socket
import tempfile

from datetime import datetime
from fabric.api import env
from fabric.api import (
    hide,
    local,
    run as fabric_run,
    sudo as fabric_sudo,
    put as fabric_put,
    get as fabric_get,
    cd as fabric_cd,
)
from fabric.decorators import task, runs_once, roles
from fabric.colors import red
from fabric.contrib import project
from fabric.contrib.files import exists, contains, append
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
    env.disable_known_hosts = True
    env.django_admin_static_path = 'site-packages/django/contrib/admin/media/'

    try:
        env.gitrev = local(
            'git describe --dirty --all --long',
            capture=True,
        )
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
    """
    Wraps a run or sudo command so that you can pass virtualenv=True to make it
    run in the python virtualenv.
    """
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

@task
@roles('web')
def ping():
    """
    Check connectivity to each server.
    """
    run('hostname')


#
# Management Commands
#


@task
@roles('system-role')
def configure_nginx(conf, name):
    env.nginx_vhost_name = name

    #grab the server's hostname, and ensure that it is a short name
    env.server_hostname = run('hostname').strip().split(".", 1)[0]
    
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
    # The crontab can either be specified as a string or in a template file.
    if getattr(env, 'crontab', None) is not None:
        put(None, '{home}/tmp/crontab', putstr=env.crontab + '\n\n')
    else:
        put('lib/tinyservicelib/deploy/crontab.template', '{home}/tmp/crontab', template=True)
    run('crontab {home}/tmp/crontab')


@task
@roles('web')
def sv(cmd, service):
    run('SVDIR={home}/service sv ' + cmd + ' ' + service)


#
# Utility functions
#

def count_unfinished_migrations():
    """
    Check whether there are no migrations that have not been run.

    Return 0 if all migrations have been run or there aren't any.
    Otherwise return a count of unfinished migrations.
    """
    with hide('running', 'stdout'):
        with cd(env.project):
            output = run(
                'source {home}/CURRENT/bin/activate && '
                './manage.py migrate --list'
            )
    return output.count('( )')

recorded_answers = {}
def get_user_confirmation(message):
    """
    Ask the user to explicitly choose to continue despite some warning message.

    This function remembers answers that have already been given, so you don't
    have to re-answer the same warning for every server.
    """
    global recorded_answers

    if message in recorded_answers:
        return recorded_answers[message]

    print red(message)

    answer = ''
    while True:
        answer = raw_input('Continue? [yes/no] ')
        if answer == 'no':
            recorded_answers[message] = False
            return False
        elif answer == 'yes':
            recorded_answers[message] = True
            return True

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


@formatargs
def sshagent_run(cmd):
    """
    Helper function.
    Runs a command with SSH agent forwarding enabled.

    Note:: Fabric (and paramiko) can't forward your SSH agent.
    This helper uses your system's ssh to do so.
    """

    if env.get('forward_agent', False):
        return run(cmd)

    # Allow specifying the port in the host string. Which we will never do.
    if ':' in env.host_string:
        host, port = env.host_string.split(':')
    else:
        host = env.host_string
        port = 22

    return local(
        'ssh '
        '-o "StrictHostKeyChecking no" '
        '-p %s '
        '-A %s '
        '"%s"'
        % (port, host, cmd)
    )


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
                'subversion', 'python-dev', 'libevent-dev', 'ntp',
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

def origin_check(intended_branch='master'):
    branch_check(intended_branch)
    push_check()

def current_git_branch():
    branch_name_long = local('git symbolic-ref -q HEAD', capture=True).strip()
    prefix = 'refs/heads/'
    assert branch_name_long.startswith(prefix)
    branch_name = branch_name_long[len(prefix):]
    return branch_name

def branch_check(intended_branch):
    # Are we on the correct deployment branch?
    branch_name = '(unnamed branch)'
    with settings(warn_only=True):
        branch_name = current_git_branch()
    if not branch_name:
        raise EnvironmentError('Could not determine current branch.')
    elif branch_name != intended_branch:
        raise EnvironmentError(
            'Local repository is not on branch "%s", it is on "%s"!'
            % (intended_branch, branch_name)
        )
    return branch_name

def push_check():
    # Is our local branch synced with the origin?
    branch_name = current_git_branch()
    git_log = "git log --no-color --pretty=format:'%H' -n1"
    origin_latest = local(git_log + ' origin/' + branch_name, capture=True)
    local_latest = local(git_log + ' ' + branch_name, capture=True)
    if origin_latest != local_latest:
        raise EnvironmentError('Local repository has un-pushed changes.')

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


@task
@roles('system-role')
def install_terrarium():
    # This is a temporary fix. The correct way to do this is through a tool
    # such as puppet, but in the meantime, we need a quick way to get this up
    # and running on existing servers.
    sudo('pip install --upgrade -e git+git://github.com/brooklynpacket/virtualenv.git#egg=virtualenv')
    sudo('pip install --upgrade -e git+git://github.com/brooklynpacket/terrarium.git#egg=terrarium')


def load_overrides_settings(overrides=None):
    #XXX: shares a bit too much with clone_from_config
    if overrides is None:
        overrides = env.overrides
    overrides_settings = {}
    execfile(overrides, {}, overrides_settings)
    if "REDIS_PORT" in overrides_settings:
        env.redis_port = overrides_settings["REDIS_PORT"]
    if "REDIS_PASSWORD" in overrides_settings:
        env.redis_password = overrides_settings["REDIS_PASSWORD"]


#
# Code uploading
#

@task
@roles('web')
def update_code():
    """
    Create a new virtualenv on the server that has the correct pip packages
    installed, and upload the code to that virtualenv.
    """
    try:
        pre_deploy_check()
        if env.environment == 'production':
            branch_check('release')
        push_check()
        lock_check()
    except EnvironmentError as e:
        if not get_user_confirmation(str(e)):
            return

    env.nowstr = str(datetime.utcnow())
    append('.fablog', '{nowstr} GMT [{base}] initiated by {deploy_user}@{deploy_hostname}.'.format(**env))
    append('.ssh/config', 'StrictHostKeyChecking=no')
    try:
        deploy_bootstrap()
        deploy_upload()
        deploy_configure()
        deploy_update()
        deploy_crontab()
    except:
        env.nowstr = str(datetime.utcnow())
        append('.fablog', '{nowstr} GMT [{base}] ERROR.'.format(**env))
        # Remove the offending directory.
        run('mv {home}/releases/{base} {home}/tmp/')
        raise
    else:
        env.nowstr = str(datetime.utcnow())
        append('.fablog', '{nowstr} GMT [{base}] DONE.'.format(**env))

# The deploy_* can't quite yet be made into a @task since env.base is set to
# the second resolution and we have no way of overriding it.
def deploy_bootstrap():
    'Create the base dir structure and bootstrap a virtualenv.'
    run('mkdir -p releases service/{runit} tmp')
    run('mkdir -p shared/{{log,run,lock,pipdcache}}')

    reqs_file = '{home}/tmp/requirements.txt'
    put('lib/tinyservicelib/deploy/requirements.txt', reqs_file)

    sshagent_run('terrarium --target {home}/releases/{base} '
                 '--s3-bucket tinyco.terrarium '
                 '--s3-access-key AKIAJ7KPC7GIYX7K42AQ ' #terrarium user
                 '--s3-secret-key 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 '
                 '--s3-max-retries 3 '
                 'install %s'
                 % (reqs_file))

    with cd('{home}/releases'):
        run('mkdir -p {base}/{{var,etc,tmp}}')

@task
@runs_once
def build_source_distribution():
    base = os.path.dirname(__file__)
    distdir = os.path.join(base, 'dist')
    local('find {0} -name MANIFEST | xargs rm'.format(base))
    local('rm -rf {0}'.format(distdir))
    local('cd lib/tinyservicelib; python setup.py sdist')
    local('python setup.py sdist')
    local('mv lib/tinyservicelib/dist/* dist')
    local('tar zvcf dist/project.tar.gz __init__.py settings.py manage.py urls.py version.py templates')

    local('bash lib/soa-protocol/bin/make_avprs.sh')

def deploy_upload():
    'Upload the project.'
    build_source_distribution()
    run('mkdir -p {project_deploy}')

    def itarball(tarball):
        put('dist/' + tarball, '{home}/releases/{base}/tmp/' + tarball)
        run('pip install {home}/releases/{base}/tmp/' + tarball, virtualenv=True)

    itarball('{package_name}-{version}.tar.gz')
    itarball('tinyservicelib-2.0.tar.gz')

    project.rsync_project('{home}/releases/{base}/etc/avpr'.format(**env), 'lib/soa-protocol/avpr/')

    put('dist/project.tar.gz', '{home}/releases/{base}/tmp/project.tar.gz')
    run('tar zxf {home}/releases/{base}/tmp/project.tar.gz -C {project_deploy}')

    # We need to remove all .pyc files.
    run("find {home}/releases/{base} -name '*.pyc' -delete")

    put('lib/tinyservicelib/bin/agglog.sh', '{home}/releases/{base}/bin/agglog.sh')
    run('chmod 755 {home}/releases/{base}/bin/agglog.sh')

def deploy_configure():
    'Build and deploy configuration files to environment.'

    run('mkdir -p {home}/releases/{base}/etc/{{service,nginx}}')
    run('mkdir -p {project_deploy}')

    put('lib/tinyservicelib/deploy/run.template', '{home}/releases/{base}/etc/service/run', template=True)
    put('lib/tinyservicelib/deploy/logrotate.conf.template', '{home}/releases/{base}/etc/logrotate.conf', template=True)
    put('lib/tinyservicelib/deploy/guconf.py.template', '{project_deploy}/guconf.py', template=True)
    put('lib/tinyservicelib/deploy/log.debug.conf', '{home}/releases/{base}/etc/log.debug.conf')

    # Assemble a .bashrc and .profile from the system skeleton default, and our templated addendums.
    # .bashrc is only run on interactive shell sessions
    put('lib/tinyservicelib/deploy/bashrc_addendum.template', '{home}/.bashrc_addendum', template=True)
    run('cat /etc/skel/.bashrc {home}/.bashrc_addendum > {home}/.bashrc')

    # .profile is run on ssh commands through fab run() as well.
    put('lib/tinyservicelib/deploy/profile_addendum.template', '{home}/.profile_addendum', template=True)
    run('cat /etc/skel/.profile {home}/.profile_addendum > {home}/.profile')

    run('rm -f {home}/.bash_aliases') # Remove bash_aliases from old deploys.

    run('chmod 755 {home}/releases/{base}/etc/service/run')

    if env.get('overrides', None) is not None:
        put(env.overrides, '{project_deploy}/overrides.py')


def deploy_update():
    'Switch the active environment.'
    # For some reason, ln -sf doesn't work x-(
    run('rm -f {home}/CURRENT')
    run('ln -sf {home}/releases/{base} {home}/CURRENT')
    run('ln -sf {home}/shared/log/runit/current {home}/shared/log/django_log')
    run('rm -f {home}/service/{runit}/run')
    run('ln -sf {home}/CURRENT/etc/service/run {home}/service/{runit}/run')


@task
@roles('web')
def flip():
    count = count_unfinished_migrations()
    if count > 0:
        # Confirm with the user whether we want to sighup anyway.
        get_user_confirmation("There are migrations that have not been run! ({} of them)".format(count))

    # TODO use runit
    sv('restart', '{runit}')

