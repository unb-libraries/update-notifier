# UNB Libraries Update Notifier

Checks a list of servers over SSH for available `apt` updates and reports them to an Amazon SNS topic.

## Installation

```
composer install
```

Copy `update-notifier.yml.sample` to `update-notifier.yml` and fill in the server list and SNS
credentials/topic ARN. The account running this needs passwordless SSH access to every listed server.

## Commands

Use `./bin/update-notifier list` for a full list of commands.

 * `apt:check` - check all configured servers for apt updates and send the results to SNS
   * `--print` - print the results instead of sending them to SNS
   * `--host` - limit the check to this host (repeatable)
