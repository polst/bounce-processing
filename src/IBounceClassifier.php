<?php

namespace Vda\BounceProcessing;

interface IBounceClassifier
{
    const TYPE_UNKNOWN  = 0;
    const TYPE_SOFT     = 1;
    const TYPE_HARD     = 2;
    const TYPE_IGNORE   = 3;

    /**
     * @param string $emailHeaders
     * @param string $emailBody
     * @return array array of [email => bounceType] $emailBody is a bounce, empty array otherwise.
     */
    public function classifyBounce(string $emailHeaders, string $emailBody): array;

    public function getSubject(string $headers): string;

    public function getEmailFromHeaders(string $type, string $headers): ?string;
}
