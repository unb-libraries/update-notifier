#!/usr/bin/env python

import json, os, subprocess, re
from optparse import OptionParser
from prettytable import PrettyTable

ec2_sns_sender_binpath = '/var/opt/ec2-sns-sender/sns_send'

class BaseApp:

  def __init__(self, host, opts):
    self.host = host
    self.options = opts

  def _run(self, args):
    ssh = ['ssh', self.host] + args
    output = subprocess.check_output(ssh, stderr=subprocess.STDOUT)
    return output

class Apt(BaseApp):

  def run_command(self):
    output = self._run(['/usr/lib/update-notifier/apt-check'])
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
      output = self._run(['cd', path, '&&', 'npm', 'outdated', '--depth=0', '--parseable'])
      for line in output.splitlines() :
        versions = line.split(':')
        old = versions[-2].split('@')
        new = versions[-3].split('@')
        if old == new : # A new version of the module exists, but we have the version we want
          continue
        module = versions[0].split('/').pop()
        results.append([path, old[1], new[1], module])
    return results

class Drupal(BaseApp):

  def run_command(self):
    results = []
    for site in self.options['sites'] :
      run_opts = ['drush', '--root=' + '/var/www/' + site + '/htdocs/', '--uri=http://default']
      self._run(run_opts + ['sql-query', '"DELETE FROM cache_update"'])
      output = self._run(run_opts + ['ups', '--format=csv', '--pipe'])
      for line in output.splitlines() :
        update = line.rstrip().split(',')
        if not re.match('^Failed', update[0]) and update[3] != 'Unknown':
          if not update[0] in self.options.get(site, {}).get('ignore', []):
            results.append([site, update[1], update[2], update[0] + ' (' + update[3].replace(' available','') + ')'])
    return results

class Composer(BaseApp):

  def run_command(self):
    results = []
    for path in self.options['paths'] :
      output = self._run(['composer.phar', '--no-ansi', '--working-dir=' + path, 'update', '--dry-run'])
      for line in output.splitlines() :
        match = re.match('^\s+- Updating ([^\s]+) \(([^\)]+)\) to ([^\s]+) \(([^\)]+)\)', output)
        if match :
          results.append([path, match.group(2), match.group(4), match.group(1)])
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

  def get_updates(self):
    table = PrettyTable(["Hostname","Type","Project","Old","New","Notes"])
    table.padding_width = 1
    table.align = "l"

    for host, apps in sorted(self.config['servers'].items()) :
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
  (options, args) = parser.parse_args()

  notifier = UpdateNotifier(args[0])
  table = notifier.get_updates()

  if options.print_only:
    print table
  else:
    notifier.send_sns(table)

if __name__ == "__main__":
  main()
