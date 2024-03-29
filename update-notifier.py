#!/usr/bin/env python

import json, os, subprocess, re, datetime
from optparse import OptionParser
from prettytable import PrettyTable

ec2_sns_sender_binpath = '/var/opt/ec2-sns-sender/sns_send'

class BaseApp:

  def __init__(self, host, opts):
    self.host = host
    self.options = opts

  def _run_ssh(self, args):
    ssh = ['ssh', self.host] + args
    try:
      output = subprocess.check_output(ssh, encoding='utf8')
    except subprocess.CalledProcessError as e:
      print("ERROR during " + ' '.join(ssh))
      output = ''
    return output

class Apt(BaseApp):

  def run_command(self):
    results = []
    output = self._run_ssh(['/usr/lib/update-notifier/apt-check', '2>&1'])
    if output == '':
      results.append(['', '', '', 'Apt Check Failed'])
    elif output != '0;0' :
      updates = output.split(';')
      if datetime.datetime.today().weekday() == 0 or updates[1] != '0' :
        result = ['', '', updates[0], '']
        if updates[1] != '0' :
          result[-1] = updates[1] + ' security updates'
          results.append(result)

    output = self._run_ssh(['[ -e "/var/run/reboot-required" ] && echo 1 || echo 0'])
    if output[0] == '1' :
      results.append(['', '', '', 'Reboot Required'])

    return results

class Npm(BaseApp):

  def run_command(self):
    results = []
    for path in self.options['paths'] :
      output = self._run_ssh(['cd', path, '&&', 'npm', 'outdated', '--depth=0', '--json', '||true'])
      if output != '' :
        updates = json.loads(output)
        for module in sorted(updates) :
          results.append([path, updates[module]['current'], updates[module]['wanted'], module])
    return results

class DrupalDocker(BaseApp):

  def run_command(self):
    results = []

    output = self._run_ssh(['kubectl', 'get', 'pods', '--all-namespaces', '-l app=drupal,appMajor=9', '-o wide']);

    seen = {}
    first_line = True
    for line in output.splitlines() :
      if first_line:
        first_line = False
        continue

      cols = line.split()
      namespace = cols[0]
      pod = cols[1]

      if namespace not in ['dev', 'prod']:
        continue

      host = re.sub('-[a-z0-9]+-[a-z0-9]+$', '', pod)
      site = host.replace('-', '.')
      host = site + ' (' + namespace + ')'

      if host in seen:
        continue
      seen[host] = 1

      run_opts = ['kubectl', 'exec', '--namespace=' + namespace, pod, '--', '/scripts/listDrupalUpdates.sh']
      if datetime.datetime.today().weekday() != 0:
        run_opts += ['-s']
      out = self._run_ssh(run_opts + ['2>/dev/null'])
      if out != '' :
        updates = json.loads(out)
        for module in updates:
          if not (module['name'] in self.options.get(site, {}).get('ignore', []) or module['recommended'] is None) :
            status = module['status'].replace(' available', '')
            results.append([host, module['existing_version'], module['recommended'], module['name'] + ' (' + status + ')'])

    return results

class Drupal(BaseApp):

  def run_command(self):
    results = []
    for site in self.options['sites'] :
      run_opts = ['drush', '--root=' + '/var/www/' + site + '/htdocs/', '--uri=http://default']
      clear_cache = ['cache-rebuild'] if self.options.get(site,{}).get('version', '') == '8' else ['cc', 'all'];
      self._run_ssh(run_opts + clear_cache + ['--pipe', '2>/dev/null'])
      self._run_ssh(run_opts + ['rf', '2>/dev/null'])
      output = self._run_ssh(run_opts + ['ups', '--update-backend=drupal', '--format=csv', '--pipe', '2>/dev/null'])
      for line in output.splitlines() :
        update = line.rstrip().split(',')
        if len(update) > 1 and not re.match('^Failed', update[0]) and not re.match('^(Unknown|Unable to check status)', update[3]):
          if not update[0] in self.options.get(site, {}).get('ignore', []):
            results.append([site, update[1], update[2], update[0] + ' (' + update[3].replace(' available','') + ')'])
    return results

class ComposerDocker(BaseApp):

  def run_command(self):
    results = []

    for app in self.options['apps'] :
      output = self._run_ssh(['kubectl', 'get', 'pods', '--all-namespaces', '-l app=' + app, '-o wide']);

      first_line = True
      for line in output.splitlines() :
        if first_line:
          first_line = False
          continue

        cols = line.split()
        namespace = cols[0]
        pod = cols[1]

        if namespace not in ['dev', 'prod']:
          continue

        host = re.sub('-[a-z0-9]+-[a-z0-9]+$', '', pod)
        site = host.replace('-', '.') + ' (' + namespace + ')'

        output = self._run_ssh(['kubectl', 'exec', '--namespace=' + namespace, pod, '--', 'composer', '--no-ansi', 'update', '--dry-run', '2>&1'])
        for line in output.splitlines() :
          match = re.match('^\s+- Updating ([^\s]+) \(([^\)]+)\) to ([^\s]+) \(([^\)]+)\)', line)
          if match :
            results.append([site, match.group(2), match.group(4), match.group(1)])
    return results

class Composer(BaseApp):

  def run_command(self):
    results = []
    for path in self.options['paths'] :
      output = self._run_ssh(['composer', '--no-ansi', '--working-dir=' + path, 'update', '--dry-run', '2>&1'])
      start = False
      for line in output.splitlines() :
        if not start:
          if re.match('Package operations', line):
            start = True
          continue
        match = re.match('^\s+- Upgrading ([^\s]+) \(([^\s]+) => ([^\s]+)\)', line)
        if match :
          results.append([path, match.group(2), match.group(3), match.group(1)])
    return results

class PipDocker(BaseApp):

  def run_command(self):
    results = []

    for app in self.options['apps'] :
      output = self._run_ssh(['kubectl', 'get', 'pods', '--all-namespaces', '-l app=' + app, '-o wide']);

      first_line = True
      for line in output.splitlines() :
        if first_line:
          first_line = False
          continue

        cols = line.split()
        namespace = cols[0]
        pod = cols[1]

        if namespace not in ['dev', 'prod']:
          continue

        host = re.sub('-[a-z0-9]+-[a-z0-9]+$', '', pod)
        site = host.replace('-', '.') + ' (' + namespace + ')'

        updates = self._run_ssh(['kubectl', 'exec', '--namespace=' + namespace, pod, '--', 'pur', '-o /dev/null'])
        for update in updates.splitlines() :
          match = re.match('Updated ([^:]+): ([^\s]+) -> ([^\s]+)', update)
          if match :
            results.append([site, match.group(2), match.group(3), match.group(1)])

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

  def get_updates(self, hosts, types):
    table = PrettyTable(["Hostname","Type","Project","Old","New","Notes"])
    table.padding_width = 1
    table.align = "l"

    for host, apps in sorted(self.config['servers'].items()) :
      if hosts != None and host not in hosts:
        continue
      for app_type, opts in sorted(apps.items()) :
        if types != None and app_type not in types:
          continue
        constructor = globals()[app_type]
        app = constructor(host, opts)
        results = app.run_command()

        for result in sorted(results, key=lambda x: x[0]) :
          row = [host, app_type] + result
          table.add_row(row)
    return table

def main():
  parser = OptionParser()
  parser.add_option('-p', '--print', dest = 'print_only', help = 'Just print the results, no SNS message.', default = False, action = 'store_true')
  parser.add_option('--host', dest = 'host', help = 'Check for updates on this host only (can be specified multiple times)', action = 'append')
  parser.add_option('--type', dest = 'type', help = 'Check for updates of this type only (can be specified multiple times)', action = 'append')
  (options, args) = parser.parse_args()

  notifier = UpdateNotifier(args[0])
  table = notifier.get_updates(hosts=options.host, types=options.type)

  if options.print_only:
    print(table)
  else:
    notifier.send_sns(table)

if __name__ == "__main__":
  main()
