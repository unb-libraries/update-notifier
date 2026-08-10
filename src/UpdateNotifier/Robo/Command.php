<?php

namespace UNBLibraries\UpdateNotifier\Robo;

use Robo\Robo;

class Command extends \Robo\Tasks
{
    public function __construct()
    {
        Robo::loadConfiguration([__DIR__ . '/../../../update-notifier.yml']);
    }

    private function getSNSClient(): \Aws\Sns\SnsClient
    {
        $config = Robo::Config()->get('sns');
        return \Aws\Sns\SnsClient::factory($config);
    }

    protected function sendSNS(string $subject, string $message): void
    {
        $this->getSNSClient()->publish([
            'TopicArn' => Robo::Config()->get('sns.topic'),
            'Subject' => $subject,
            'Message' => $message,
        ]);
    }

    /**
     * @phpstan-return string[]
     */
    protected function getServers(): array
    {
        return Robo::Config()->get('servers') ?? [];
    }
}
