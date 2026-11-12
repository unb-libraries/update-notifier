<?php

namespace UNBLibraries\Tests\UpdateNotifier\Robo;

use UNBLibraries\UpdateNotifier\Robo\AptCommand;

/**
 * An AptCommand whose servers, SSH responses and SNS publishing are fakes.
 */
class FakeAptCommand extends AptCommand
{
    /**
     * @phpstan-var array<int, array{host: string, command: string}>
     */
    public array $sshCalls = [];

    /**
     * @phpstan-var array<int, array{subject: string, message: string}>
     */
    public array $sent = [];

  /**
   * @phpstan-param string[] $servers
   * @phpstan-param array<string, array{apt: string, reboot: string}> $responses
   *   Per host: the apt-check output and the reboot-required check output.
   */
    public function __construct(private array $servers, private array $responses)
    {
        // Skips loading update-notifier.yml.
    }

    protected function getServers(): array
    {
        return $this->servers;
    }

    protected function sshExec(string $host, string $command): string
    {
        $this->sshCalls[] = ['host' => $host, 'command' => $command];
        $response = $this->responses[$host] ?? ['apt' => '', 'reboot' => ''];
        return str_contains($command, 'apt-check') ? $response['apt'] : $response['reboot'];
    }

    protected function sendSNS(string $subject, string $message): void
    {
        $this->sent[] = ['subject' => $subject, 'message' => $message];
    }
}
