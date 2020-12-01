<?php

namespace Vda\BounceProcessing;

interface IBounceClassifier
{
    const TYPE_UNKNOWN  = 0;
    const TYPE_SOFT     = 1;
    const TYPE_HARD     = 2;
    const TYPE_IGNORE   = 3;

    const CATEGORY_NO_SUCH_EMAIL     = 'nosuchemail';
    const CATEGORY_INACTIVE_EMAIL    = 'inactive';
    const CATEGORY_INVALID_EMAIL     = 'invalidemail';

    const CATEGORY_BLACKLISTED       = 'blacklisted';
    const CATEGORY_BLOCKED_CONTENT   = 'blockedcontent';
    const CATEGORY_OVERQUOTA         = 'overquota';

    const CATEGORY_AUTOANSWER        = 'autoanswer';
    const CATEGORY_FEEDBACK_LOOP     = 'fbl';
    const CATEGORY_DMARC_REPORT      = 'dmarcreport';
    const CATEGORY_READ_CONFIRMATION = 'readconfirmation';

    const CATEGORY_TEMPORARY_ERROR   = 'temporaryerror';
    const CATEGORY_CONFIG_ERROR      = 'configerror';
    const CATEGORY_RELAY_ERROR       = 'relayerror';
    const CATEGORY_LOOP_ERROR        = 'looperror';

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
