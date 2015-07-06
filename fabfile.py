from fabric.api import task, local


@task
def snort():
    local('python hpigrelay.py start')
    local('snort -i em1 -A unsock -l /tmp -c /etc/snort/etc/snort.conf')


@task
def snort_restart():
    local('python hpigrelay.py restart')
    local('snort -i em1 -A unsock -l /tmp -c /etc/snort/etc/snort.conf')


@task
def start():
    local('python hpigrelay.py start')


@task
def stop():
    local('python hpigrelay.py stop')


@task
def restart():
    local('python hpigrelay.py restart')


@task
def clean():
    local('rm -rf /tmp/snort_alert')


@task
def kill():
    local("ps -ef | grep 'python hpigrelay.py' | awk '{print $2}' | xargs kill -9")
