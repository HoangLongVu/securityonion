# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states and GLOBALS.os == 'OEL' %}
{# {%  if 'stig' in salt['pillar.get']('features', []) %} #} #disabled for testing

# Need to split into enabled.sls / disabled.sls and add default.yaml + soc_default.yaml so that stigs have to be enabled from SOC UI and avoid unintentional application
# Stigs should only be applied if OS is OL9, license feature is active, and stig is enabled in SOC UI
oscap_packages:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
        - openscap
        - openscap-scanner
        - scap-security-guide

make_some_dirs:
  file.directory:
    - name: /opt/so/log/stig
    - user: socore
    - group: socore
    - makedirs: True

make_more_dir:
  file.directory:
    - name: /opt/so/conf/stig
    - user: socore
    - group: socore
    - makedirs: True

update_stig_profile:
  file.managed:
    - name: /opt/so/conf/stig/SOS-ol9-ds-CAT1-CAT2.xml
    - source: salt://stig/files/SOS-ol9-ds-CAT1-CAT2.xml
    - user: socore
    - group: socore
    - mode: 0644

update_remediation_script:
  file.managed:
    - name: /usr/sbin/so-stig
    - source: salt://stig/files/so-stig
    - user: socore
    - group: socore
    - mode: 0755
    - template: jinja

run_remediation_script:
  cmd.run:
    - name: /usr/sbin/so-stig 2>&1 > /opt/so/log/stig/stig-$(date +%Y%m%d-%H%M%S).log

remove_old_stig_logs:
  cmd.run:
    - name: find /opt/so/log/stig -type f -mtime +2 -exec rm -f {} \;

stig_remediate_schedule:
  schedule.present:
    - function: state.apply
    - job_args:
      - stig
    - hours: 12
    - maxrunning: 1
    - enabled: true

{# {%  endif %} #}
{% endif %}