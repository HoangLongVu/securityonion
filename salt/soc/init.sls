{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'soc/merged.map.jinja' import DOCKER_EXTRA_HOSTS %}

include:
  - manager.sync_es_users

socdir:
  file.directory:
    - name: /opt/so/conf/soc
    - user: 939
    - group: 939
    - makedirs: True

socdatadir:
  file.directory:
    - name: /nsm/soc/jobs
    - user: 939
    - group: 939
    - makedirs: True

soclogdir:
  file.directory:
    - name: /opt/so/log/soc
    - user: 939
    - group: 939
    - makedirs: True

socsaltdir:
  file.directory:
    - name: /opt/so/conf/soc/salt
    - user: 939
    - group: 939
    - makedirs: True

socconfig:
  file.managed:
    - name: /opt/so/conf/soc/soc.json
    - source: salt://soc/files/soc/soc.json.jinja
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja
    - show_changes: False

socmotd:
  file.managed:
    - name: /opt/so/conf/soc/motd.md
    - source: salt://soc/files/soc/motd.md
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socbanner:
  file.managed:
    - name: /opt/so/conf/soc/banner.md
    - source: salt://soc/files/soc/banner.md
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

soc_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://soc/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#soc_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://soc/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

soccustom:
  file.managed:
    - name: /opt/so/conf/soc/custom.js
    - source: salt://soc/files/soc/custom.js
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

soccustomroles:
  file.managed:
    - name: /opt/so/conf/soc/custom_roles
    - source: salt://soc/files/soc/custom_roles
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socusersroles:
  file.exists:
    - name: /opt/so/conf/soc/soc_users_roles
    - require:
      - sls: manager.sync_es_users

salt-relay:
  cron.present:
  - name: 'ps -ef | grep salt-relay.sh | grep -v grep > /dev/null 2>&1 || /opt/so/saltstack/default/salt/soc/files/bin/salt-relay.sh >> /opt/so/log/soc/salt-relay.log 2>&1 &'
  - identifier: salt-relay

so-soc:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-soc:{{ GLOBALS.so_version }}
    - hostname: soc
    - name: so-soc
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-soc'].ip }}
    - binds:
      - /nsm/soc/jobs:/opt/sensoroni/jobs:rw
      - /opt/so/log/soc/:/opt/sensoroni/logs/:rw
      - /opt/so/conf/soc/soc.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/conf/soc/motd.md:/opt/sensoroni/html/motd.md:ro
      - /opt/so/conf/soc/banner.md:/opt/sensoroni/html/login/banner.md:ro
      - /opt/so/conf/soc/custom.js:/opt/sensoroni/html/js/custom.js:ro
      - /opt/so/conf/soc/custom_roles:/opt/sensoroni/rbac/custom_roles:ro
      - /opt/so/conf/soc/soc_users_roles:/opt/sensoroni/rbac/users_roles:rw
      - /opt/so/conf/soc/salt:/opt/sensoroni/salt:rw
      - /opt/so/saltstack:/opt/so/saltstack:rw
    - extra_hosts: {{ DOCKER_EXTRA_HOSTS }}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-soc'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - watch:
      - file: /opt/so/conf/soc/*
    - require:
      - file: socdatadir
      - file: soclogdir
      - file: socconfig
      - file: socmotd
      - file: socbanner
      - file: soccustom
      - file: soccustomroles
      - file: socusersroles

append_so-soc_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-soc

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
