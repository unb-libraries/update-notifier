<?php

namespace UNBLibraries\UpdateNotifier\Robo;

use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Output\BufferedOutput;

class AptCommand extends Command
{
    private const APT_CHECK_BIN = '/usr/lib/update-notifier/apt-check';

    private const REBOOT_REQUIRED_FILE = '/var/run/reboot-required';

  /**
   * Checks all configured servers for available apt updates.
   *
   * @option $print Print the results instead of sending them to SNS.
   * @option $host Limit the check to this host (repeatable).
   *
   * @phpstan-param array<string, mixed> $opts
   *
   * @command apt:check
   */
    public function check(array $opts = ['print' => false, 'host' => []]): void
    {
        $rows = $this->getUpdateRows($opts['host']);

        if ($opts['print']) {
            $this->printRows($rows);
            return;
        }

        $this->sendSNS(
            'Available Updates',
            $rows ? $this->formatRows($rows) : 'No updates available.'
        );
    }

  /**
   * @phpstan-param string[] $hostFilter
   * @phpstan-return array<int, array{0: string, 1: string, 2: string}>
   */
    private function getUpdateRows(array $hostFilter): array
    {
        $servers = $this->getServers();
        sort($servers);

        $rows = [];
        foreach ($servers as $host) {
            if ($hostFilter && !in_array($host, $hostFilter, true)) {
                continue;
            }
            $row = $this->checkHost($host);
            if ($row !== null) {
                $rows[] = [$host, ...$row];
            }
        }

        return $rows;
    }

  /**
   * @phpstan-return array{0: string, 1: string}|null
   */
    private function checkHost(string $host): ?array
    {
        $updates = '';
        $notes = [];

        $output = trim($this->sshExec($host, self::APT_CHECK_BIN . ' 2>&1'));
        if ($output === '') {
            $notes[] = 'Apt check failed';
        } elseif ($output !== '0;0') {
            [$total, $security] = array_pad(explode(';', $output, 2), 2, '0');
            $updates = $total;
            if ($security !== '0') {
                $notes[] = "{$security} security updates";
            }
        }

        $rebootRequired = $this->sshExec(
            $host,
            sprintf('[ -e "%s" ] && echo 1 || echo 0', self::REBOOT_REQUIRED_FILE)
        );
        if (trim($rebootRequired) === '1') {
            $notes[] = 'Reboot required';
        }

        if ($updates === '' && !$notes) {
            return null;
        }

        return [$updates, implode(', ', $notes)];
    }

    private function sshExec(string $host, string $command): string
    {
        $result = $this->taskSshExec($host)
            ->exec($command)
            ->printOutput(false)
            ->printMetadata(false)
            ->run();

        return (string) $result->getMessage();
    }

  /**
   * @phpstan-param array<int, array{0: string, 1: string, 2: string}> $rows
   */
    private function printRows(array $rows): void
    {
        if (!$rows) {
            $this->io()->success('No updates available.');
            return;
        }

        $table = new Table($this->output());
        $table->setHeaders(['Hostname', 'Updates', 'Note']);
        $table->setRows($rows);
        $table->render();
    }

  /**
   * @phpstan-param array<int, array{0: string, 1: string, 2: string}> $rows
   */
    private function formatRows(array $rows): string
    {
        $output = new BufferedOutput();
        $table = new Table($output);
        $table->setHeaders(['Hostname', 'Updates', 'Note']);
        $table->setRows($rows);
        $table->render();

        return $output->fetch();
    }
}
