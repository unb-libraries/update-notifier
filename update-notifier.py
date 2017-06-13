#!/usr/bin/env python

import json, os, subprocess, re
from optparse import OptionParser
from prettytable import PrettyTable

ec2_sns_sender_binpath = '/var/opt/ec2-sns-sender/sns_send'

class BaseApp:

  def __init__(self, host, opts):
    self.host = host
    self.options = opts

  def _run_ssh(self, args):
    ssh = ['ssh', self.host] + args
    output = subprocess.check_output(ssh)
    return output

class Apt(BaseApp):

  def run_command(self):
    output = self._run_ssh(['/usr/lib/update-notifier/apt-check', '2>&1'])
    if output == '0;0' :
      return []

    updates = output.split(';')
    result = ['', '', updates[0], '']
    if updates[1] != '0' :
      result[-1] = updates[1] + ' security updates'
    return [result]

class Npm(BaseApp):

  def run_command(self):
    results = []
    for path in self.options['paths'] :
      output = self._run_ssh(['cd', path, '&&', 'npm', 'outdated', '--depth=0', '--parseable'])
      for line in output.splitlines() :
        versions = line.split(':')
        old = versions[-2].split('@')
        new = versions[-3].split('@')
        if old == new : # A new version of the module exists, but we have the version we want
          continue
        module = versions[0].split('/').pop()
        results.append([path, old[1], new[1], module])
    return results

class DrupalDocker(BaseApp):

  def run_command(self):
    results = []

    output = self._run_ssh(['sudo', 'docker', 'ps', '--format "{{.ID}} {{.Names}}"', '-f label=ca.unb.lib.generator=drupal8']);
    for line in output.splitlines() :
      cols = line.split()
      host = cols[1]
      if host.startswith('k8s_') :
        match = re.match('^k8s_([^.]+).*_(dev|prod)_', host)
        host = match.group(1) + ' (' + match.group(2) + ')'
      # Check for newrelic updates
      nr_exists = self._run_ssh(['sudo', 'docker', 'exec', cols[0], 'which', 'newrelic-daemon']).splitlines()[0]
      if nr_exists != '':
        nr_ver_line = self._run_ssh(['sudo', 'docker', 'exec', cols[0], 'newrelic-daemon', '--version']).splitlines()[0]
        nr_ver_string = re.search('\d+.\d+.\d+.\d+', nr_ver_line).group()
        nr_res_code = subprocess.check_output(['curl', '-s', '-o', '/dev/null', '-I', '-w', '%{http_code}', 'https://download.newrelic.com/php_agent/release/newrelic-php5-' + nr_ver_string + '-linux.tar.gz'])
        if nr_res_code == '404':
          results.append([host, nr_ver_string, '', 'NEWRELIC_PHP_VERSION'])
      updates = self._run_ssh(['sudo', 'docker', 'exec', cols[0], 'drush', 'ups', '--root=/app/html', '--update-backend=drupal', '--format=csv', '--pipe', '2>/dev/null'])
      for update_line in updates.splitlines() :
        update = update_line.rstrip().split(',')
        if len(update) > 1 and not re.match('^Failed', update[0]) and not re.match('^(Unknown|Unable to check status)', update[3]):
          results.append([host, update[1], update[2], update[0] + ' (' + update[3].replace(' available','') + ')'])

    return results

class Drupal(BaseApp):

  def run_command(self):
    results = []
    for site in self.options['sites'] :
      run_opts = ['drush', '--root=' + '/var/www/' + site + '/htdocs/', '--uri=http://default']
      clear_cache = ['cache-rebuild'] if self.options.get(site,{}).get('version', '') == '8' else ['cc', 'all'];
      self._run_ssh(run_opts + clear_cache + ['--pipe', '2>/dev/null'])
      output = self._run_ssh(run_opts + ['ups', '--update-backend=drupal', '--format=csv', '--pipe', '2>/dev/null'])
      for line in output.splitlines() :
        update = line.rstrip().split(',')
        if len(update) > 1 and not re.match('^Failed', update[0]) and not re.match('^(Unknown|Unable to check status)', update[3]):
          if not update[0] in self.options.get(site, {}).get('ignore', []):
            results.append([site, update[1], update[2], update[0] + ' (' + update[3].replace(' available','') + ')'])
    return results

class Composer(BaseApp):

  def run_command(self):
    results = []
    for path in self.options['paths'] :
      output = self._run_ssh(['composer.phar', '--no-ansi', '--working-dir=' + path, 'update', '--dry-run', '2>&1'])
      for line in output.splitlines() :
        match = re.match('^\s+- Updating ([^\s]+) \(([^\)]+)\) to ([^\s]+) \(([^\)]+)\)', line)
        if match :
          results.append([path, match.group(2), match.group(4), match.group(1)])
    return results

class Pip(BaseApp):

  def run_command(self):
    results = []
    for path in self.options['paths'] :
      output = self._run_ssh(['cd', path, '&&', 'pur', '-o', '/dev/null'])
      for line in output.splitlines() :
        match = re.match('Updated ([^:]+): ([^\s]+) -> ([^\s]+)', line)
        if match :
          results.append([path, match.group(2), match.group(3), match.group(1)])
    return results

class UpdateNotifier:

  def __init__(self, config_file):
    self.config = json.load(open(config_file))

  def send_sns(self, table):
    DEVNULL = open(os.devnull, 'w')
    subject = "Available Updates"
    message = "No updates available."
    if table.rowcount > 0:
      message = table.get_string()
    subprocess.call([ec2_sns_sender_binpath, '-t', self.config['sns-topic'], '-s', subject, '-m', message], stdout=DEVNULL, stderr=DEVNULL)

  def get_updates(self, hosts):
    table = PrettyTable(["Hostname","Type","Project","Old","New","Notes"])
    table.padding_width = 1
    table.align = "l"

    for host, apps in sorted(self.config['servers'].items()) :
      if hosts != None and host not in hosts:
        continue
      for app_type, opts in sorted(apps.items()) :
        constructor = globals()[app_type]
        app = constructor(host, opts)
        results = app.run_command()

        for result in results :
          row = [host, app_type] + result
          table.add_row(row)
    return table

def main():
  parser = OptionParser()
  parser.add_option('-p', '--print', dest = 'print_only', help = 'Just print the results, no SNS message.', default = False, action = 'store_true')
  parser.add_option('--host', dest = 'host', help = 'Check for updates on this host only (can be specified multiple times)', action = 'append')
  (options, args) = parser.parse_args()

  notifier = UpdateNotifier(args[0])
  table = notifier.get_updates(hosts=options.host)

  if options.print_only:
    print table
  else:
    notifier.send_sns(table)

if __name__ == "__main__":
  main()
