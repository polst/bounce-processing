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
     * @return array containing the following keys:
     * - emails: array of emails found in the body
     * - bounceType: assigned bounce type
     * - category: pattern category
     * - pattern: matched pattern
     * - reason: original string in the email that matched the pattern
     */
    function classifyBounce(string $emailHeaders, string $emailBody): array;

    function getSubject(string $headers): string;

    function getEmailFromHeaders(string $type, string $headers): ?string;
}
