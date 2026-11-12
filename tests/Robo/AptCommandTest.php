<?php

namespace UNBLibraries\Tests\UpdateNotifier\Robo;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;

class AptCommandTest extends TestCase
{
    private BufferedOutput $output;

  /**
   * @phpstan-param string[] $servers
   * @phpstan-param array<string, array{apt: string, reboot: string}> $responses
   */
    private function command(array $servers, array $responses, int $verbosity = OutputInterface::VERBOSITY_NORMAL): FakeAptCommand
    {
        $command = new FakeAptCommand($servers, $responses);
        $this->output = new BufferedOutput($verbosity);
        $command->setInput(new ArrayInput([]));
        $command->setOutput($this->output);
        return $command;
    }

  /**
   * @phpstan-param array<string, mixed> $opts
   */
    private function runCheck(FakeAptCommand $command, array $opts = []): void
    {
        $command->check($opts + ['print' => false, 'host' => []]);
    }

  /**
   * The Updates and Note columns reported for one host, or null when it isn't reported.
   *
   * @phpstan-return array{0: string, 1: string}|null
   */
    private function hostRow(string $apt, string $reboot): ?array
    {
        $command = $this->command(['host1'], ['host1' => ['apt' => $apt, 'reboot' => $reboot]]);
        $this->runCheck($command);
        if ($command->sent[0]['message'] === 'No updates available.') {
            return null;
        }
        foreach (explode("\n", $command->sent[0]['message']) as $line) {
            if (str_starts_with($line, '| host1')) {
                $cells = array_map('trim', explode('|', trim($line, '|')));
                return [$cells[1], $cells[2]];
            }
        }
        self::fail('host1 row not found in: ' . $command->sent[0]['message']);
    }

  /**
   * @phpstan-return array<string, array{0: string, 1: string, 2: array{0: string, 1: string}|null}>
   */
    public static function hostResults(): array
    {
        return [
            'up to date' => ["0;0\n", "0\n", null],
            'updates, none security' => ["3;0\n", "0\n", ['3', '']],
            'updates with security' => ["5;2\n", "0\n", ['5', '2 security updates']],
            'reboot only' => ["0;0\n", "1\n", ['', 'Reboot required']],
            'updates and reboot' => ["4;1\n", "1\n", ['4', '1 security updates, Reboot required']],
            'apt-check gave no output' => ['', "0\n", ['', 'Apt check failed']],
            'apt-check failed, reboot required' => ['', "1\n", ['', 'Apt check failed, Reboot required']],
            'reboot check output not exactly 1' => ["0;0\n", "yes\n", null],
        ];
    }

  /**
   * @phpstan-param array{0: string, 1: string}|null $expected
   */
    #[DataProvider('hostResults')]
    public function testHostResult(string $apt, string $reboot, ?array $expected): void
    {
        $this->assertSame($expected, $this->hostRow($apt, $reboot));
    }

    public function testNonNumericAptCheckOutputIsReportedVerbatimAsTheUpdateCount(): void
    {
        // Documents current behaviour: apt-check's output is read with 2>&1, so an error
        // message (rather than "N;M") lands in the Updates column instead of being reported
        // as "Apt check failed".
        $this->assertSame(
            ['E: some apt error', ''],
            $this->hostRow("E: some apt error\n", "0\n")
        );
    }

    public function testRunsAptCheckAndRebootCheckOverSsh(): void
    {
        $command = $this->command(['host1'], ['host1' => ['apt' => '0;0', 'reboot' => '0']]);
        $this->runCheck($command);

        $this->assertSame(
            [
                ['host' => 'host1', 'command' => '/usr/lib/update-notifier/apt-check 2>&1'],
                ['host' => 'host1', 'command' => '[ -e "/var/run/reboot-required" ] && echo 1 || echo 0'],
            ],
            $command->sshCalls
        );
    }

    public function testSendsNoUpdatesMessageWhenNothingToReport(): void
    {
        $command = $this->command(
            ['host1', 'host2'],
            ['host1' => ['apt' => '0;0', 'reboot' => '0'], 'host2' => ['apt' => '0;0', 'reboot' => '0']]
        );
        $this->runCheck($command);

        $this->assertSame([['subject' => 'Available Updates', 'message' => 'No updates available.']], $command->sent);
    }

    public function testSendsOneTableOfHostsSortedByName(): void
    {
        $command = $this->command(
            ['zeta.example.com', 'alpha.example.com', 'mid.example.com'],
            [
                'zeta.example.com' => ['apt' => '2;1', 'reboot' => '0'],
                'alpha.example.com' => ['apt' => '7;0', 'reboot' => '1'],
                'mid.example.com' => ['apt' => '0;0', 'reboot' => '0'],
            ]
        );
        $this->runCheck($command);

        $this->assertCount(1, $command->sent);
        $this->assertSame('Available Updates', $command->sent[0]['subject']);
        $expected = <<<'TABLE'
            +-------------------+---------+--------------------+
            | Hostname          | Updates | Note               |
            +-------------------+---------+--------------------+
            | alpha.example.com | 7       | Reboot required    |
            | zeta.example.com  | 2       | 1 security updates |
            +-------------------+---------+--------------------+

            TABLE;
        $this->assertSame($expected, $command->sent[0]['message']);
        $this->assertSame(
            ['alpha.example.com', 'alpha.example.com', 'mid.example.com', 'mid.example.com', 'zeta.example.com', 'zeta.example.com'],
            array_column($command->sshCalls, 'host')
        );
    }

    public function testHostFilterLimitsWhichServersAreChecked(): void
    {
        $command = $this->command(
            ['host1', 'host2', 'host3'],
            ['host1' => ['apt' => '1;0', 'reboot' => '0'], 'host3' => ['apt' => '2;0', 'reboot' => '0']],
            OutputInterface::VERBOSITY_VERBOSE
        );
        $this->runCheck($command, ['host' => ['host3', 'host1']]);

        $this->assertSame(['host1', 'host1', 'host3', 'host3'], array_column($command->sshCalls, 'host'));
        $this->assertStringContainsString('Skipping host2: not in --host filter', $this->output->fetch());
    }

    public function testHostFilterMatchingNoServerReportsNothing(): void
    {
        $command = $this->command(['host1'], ['host1' => ['apt' => '1;0', 'reboot' => '0']]);
        $this->runCheck($command, ['host' => ['unknown']]);

        $this->assertSame([], $command->sshCalls);
        $this->assertSame('No updates available.', $command->sent[0]['message']);
    }

    public function testPrintShowsTableInsteadOfSending(): void
    {
        $command = $this->command(['host1'], ['host1' => ['apt' => '5;2', 'reboot' => '1']]);
        $this->runCheck($command, ['print' => true]);

        $this->assertSame([], $command->sent);
        $printed = $this->output->fetch();
        $this->assertStringContainsString('Hostname', $printed);
        $this->assertMatchesRegularExpression('/host1\s*\|\s*5\s*\|\s*2 security updates, Reboot required/', $printed);
    }

    public function testPrintWithNothingToReport(): void
    {
        $command = $this->command(['host1'], ['host1' => ['apt' => '0;0', 'reboot' => '0']]);
        $this->runCheck($command, ['print' => true]);

        $this->assertSame([], $command->sent);
        $this->assertStringContainsString('No updates available.', $this->output->fetch());
    }

    public function testVerboseOutputLogsEachCheck(): void
    {
        $command = $this->command(['host1'], ['host1' => ['apt' => '', 'reboot' => '0']], OutputInterface::VERBOSITY_VERBOSE);
        $this->runCheck($command);

        $log = $this->output->fetch();
        $this->assertStringContainsString('Checking host1', $log);
        $this->assertStringContainsString('apt-check output for host1: (empty)', $log);
        $this->assertStringContainsString('reboot-required check for host1: 0', $log);
    }

    public function testQuietAtNormalVerbosity(): void
    {
        $command = $this->command(['host1'], ['host1' => ['apt' => '1;0', 'reboot' => '0']]);
        $this->runCheck($command);

        $this->assertSame('', $this->output->fetch());
    }
}
