# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from "curator/map.jinja" import CURATOROPTIONS %}
{% from "curator/map.jinja" import CURATORMERGED %}
{% set REMOVECURATORCRON = False %}

# Curator
# Create the group
curatorgroup:
  group.present:
    - name: curator
    - gid: 934

# Add user
curator:
  user.present:
    - uid: 934
    - gid: 934
    - home: /opt/so/conf/curator
    - createhome: False

# Create the log directory
curlogdir:
  file.directory:
    - name: /opt/so/log/curator
    - user: 934
    - group: 939

curactiondir:
  file.directory:
    - name: /opt/so/conf/curator/action
    - user: 934
    - group: 939
    - makedirs: True

actionconfs:
  file.recurse:
    - name: /opt/so/conf/curator/action
    - source: salt://curator/files/action
    - user: 934
    - group: 939
    - template: jinja
    - defaults:
        CURATORMERGED: {{ CURATORMERGED }}
        
curconf:
  file.managed:
    - name: /opt/so/conf/curator/curator.yml
    - source: salt://curator/files/curator.yml
    - user: 934
    - group: 939
    - mode: 660
    - template: jinja
    - show_changes: False

curclusterclose: 
  file.managed:
    - name: /usr/sbin/so-curator-cluster-close
    - source: salt://curator/files/bin/so-curator-cluster-close
    - user: 934
    - group: 939
    - mode: 755
    - template: jinja

curclusterdelete:
  file.managed:
    - name: /usr/sbin/so-curator-delete
    - source: salt://curator/files/bin/so-curator-cluster-delete
    - user: 934
    - group: 939
    - mode: 755

curclusterdeletedelete:
  file.managed:
    - name: /usr/sbin/so-curator-cluster-delete-delete
    - source: salt://curator/files/bin/so-curator-cluster-delete-delete
    - user: 934
    - group: 939
    - mode: 755
    - template: jinja

so-curator:
  docker_container.{{ CURATOROPTIONS.status }}:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-curator:{{ GLOBALS.so_version }}
    - start: {{ CURATOROPTIONS.start }}
    - hostname: curator
    - name: so-curator
    - user: curator
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-curator'].ip }}
    - interactive: True
    - tty: True
    - binds:
      - /opt/so/conf/curator/curator.yml:/etc/curator/config/curator.yml:ro
      - /opt/so/conf/curator/action/:/etc/curator/action:ro
      - /opt/so/log/curator:/var/log/curator:rw
    - require:
      - file: actionconfs
      - file: curconf
      - file: curlogdir
    - watch:
      - file: curconf

append_so-curator_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-curator
    - unless: grep -q so-curator /opt/so/conf/so-status/so-status.conf
  {% if not CURATOROPTIONS.start %}
so-curator_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-curator$
  {% else %}
delete_so-curator_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-curator$
  {% endif %}

so-curatorclusterclose:
  cron.present:
    - name: /usr/sbin/so-curator-cluster-close > /opt/so/log/curator/cron-close.log 2>&1
    - user: root
    - minute: '2'
    - hour: '*/1'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

so-curatorclusterdeletecron:
  cron.present:
    - name: /usr/sbin/so-curator-cluster-delete-delete > /opt/so/log/curator/cron-cluster-delete.log 2>&1
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
