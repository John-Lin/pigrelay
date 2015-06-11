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
def hpigrelay():
    local('python hpigrelay.py &')


@task
def clean():
    local('rm -rf /tmp/*')
