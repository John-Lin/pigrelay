from fabric.api import task, local


@task
def snort_unsock():
    local('snort -i em1 -A unsock -l /tmp -c /etc/snort/etc/snort.conf')


@task
def snort_console():
    local('snort -i em1 -c /etc/snort/etc/snort.conf -A console')


@task
def pigrelay():
    local('python pigrelay.py &')


@task
def hpigrelay_start():
    local('python hpigrelay.py start')


@task
def hpigrelay_stop():
    local('python hpigrelay.py stop')


@task
def hpigrelay_restart():
    local('python hpigrelay.py restart')


@task
def clean():
    local('rm -rf /tmp/snort_alert')


@task
def kill_pigrelay():
    local("ps -ef | grep 'python hpigrelay.py' | awk '{print $2}' | xargs kill -9")
