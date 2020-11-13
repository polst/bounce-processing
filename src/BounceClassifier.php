<?php

namespace Vda\BounceProcessing;

use Vda\Log\ILogService;

class BounceClassifier implements IBounceClassifier
{
    const BOUNCE_TYPE_MNEMONICS = [
        IBounceClassifier::TYPE_UNKNOWN => 'unknown',
        IBounceClassifier::TYPE_SOFT    => 'soft',
        IBounceClassifier::TYPE_HARD    => 'hard',
        IBounceClassifier::TYPE_IGNORE  => 'ignore',
    ];

    private $logger;
    private $excludeEmails;     // initialized in constructor
    private $bounceRules;       // prepared in constructor

    private $sourceRules = [

        self::TYPE_HARD => [

            'emaildoesntexist' => [

                '550 5.1.1 RESOLVER.ADR.RecipNotFound',
                'Message was not accepted -- invalid mailbox. Local mailbox .+? is unavailable: user not found',
                'Message was not accepted -- invalid mailbox. Local mailbox .+? is unavailable: account is disabled',
                'Message was not accepted -- invalid mailbox. Local mailbox .+? is unavailable: user is terminated',
                'LOCAL module\(account .+?\) reports: mail receiving disabled',
                'This is a permanent error. The following address\(es\) failed:.+?Unknown user',
                'This is a permanent error. The following address\(es\) failed:.+?Unrouteable address',
                '5.1.0 - Unknown address error 553-\'Invalid/inactive user',
                '550-5.1.1 The email account that you tried to reach does not exist',
                '550 5.1.1 User unknown',
                'Recipient address rejected: Your emails has been returned because the intented recipient\'s email account has been suspended',
                '550 "Unknown user for this domain"',
                'Podane konto jest zablokowane administracyjnie lub nieaktywne / This account is disabled or not yet active',
                'Podane konto nie istnieje / No mailbox here by that name',
                'This user doesn\'t have a .+? e-mailaccount',
                'This account has been disabled or discontinued',
                'The ESMTP Mail System program.+?: unknown user:',
                '550 5.7.1 .+?: Recipient address rejected: Account closed',
                '550 5.5.0 Requested action not taken: mailbox unavailable',
                '550 .+?unknown user account',
			    '55\d:? Recipient address rejected: (Inactive user|User unknown)',
				'550-5.1.1 The email account that you tried to reach does not exist',
				'550 5.1.1 unknown or illegal alias',
				'550 5.7.1 No such user',
                '550 Requested action not taken: mailbox unavailable',
                '5\d\d .+?: Recipient address rejected: User unknown in local recipient table',
                '5\d\d .+?: Recipient address rejected: User unknown in virtual mailbox table',
                '551 .+?: user unknown or mailbox full',
                '540 5.7.1 .+?: recipient address rejected: Blocked',
                '504 Mailbox is disabled',
                '550 5.7.1 Message rejected \(no valid recipients\)',
                '550 5.1.1 Not our Customer',
                '550: Requested action not taken: mailbox unavailable',
                '550 5.1.1 .+? recipient rejected \(mailbox locked\)',
                '550 5.1.1 .+? Recipient Rejected',
                '550 5.1.1 Account not found \/ Nie ma takiego konta',
                '550 5.1.1 .+?: user does not exist',
                '550 5.1.1 .+?: Email address could not be found, or was misspelled',
                '554 Mailaddress is administratively disabled',
                '550 No such person at this address',
                '550 "User inactive"',
                '550-Unknown/invalid recipient',
                '550 Recipient Rejected: No account by that name here',
                '550-e-mail address .+? doesn\'t exist or blocked or 550 mailbox is full',
                '550-5.2.1 The email account that you tried to reach is disabled',
                '554 Invalid mailbox',
                'Your message wasn\'t delivered to .+? because the address couldn\'t be found',
                '550 5.2.1 The email account that you tried to reach is disabled',
                '540 5.7.1 .+?recipient address rejected: Inactive',
                '553 5.3.0.+?No such user',
                '5(0|5)0 No such user \(in reply to RCPT TO command\)',
                '550 Mailbox unavailable',
                '540 5.7.1.+?Recipient address rejected: Account locked by abuse team',
                '540 5.7.1.+?Recipient address rejected: Account deleted by user',
                '550 User not found',
                '550 5.1.1 Bad destination mailbox addres',
                '550 Unknown user',
                '550 "Unknown User"',
                '55\d 5.\d.\d .+?User unknown',
                '55\d .+?User unknown',
                '55\d .+?Recipient unknown',
                '550 .+? mail receiving disabled',
                '511 sorry, no mailbox here by that name',
                '554 5.2.1 No such user yet',
                '550 5.1.1.+?... User unknown',
                '550 5.1.1 Recipient address rejected: User unknown',
                '550 #5.1.0 Address rejected',
                '550 Unrouteable address',
                '550 Invalid Recipient',
                '550 5.2.1 The email account that you tried to reach is disabled',
                '55\d 5\.\d\.\d .+?: Recipient address rejected',
                '550-5.2.1 Mailbox unavailable',
                '550-5.1.1 The email account that you tried to reach does not exist',
                '550 5.1.1.+?Mailbox is not available',
                '550 5.0.0 .+? This is user have no mail',
                '550 sorry, no mailbox here by that name',
                '550 Recipient rejected: User .+? not found',
                '550 .*?No Such User',
                '550 No such recipient',
                '550 .+? user not found',
                '50\d Bad address syntax',
                '550 Failed to deliver to address',
                '550 rejected: Unknown recipient',
                '550 .+?Mailbox .+? does not exist',
                '550 5.1.1 .+?Recipient .+? does not exist',
                '550-5.2.1 The email account that you tried to reach is disabled',
                '554 delivery error: [\d\.]* Sorry, your message to .+? cannot be delivered. This mailbox is disabled',
                '550 5.1.1 .*?Recipient not found',
                '550 "Error 60: No mailbox',
                '550-Invalid recipient',
                '554 5.7.1 User .+? cannot receive email',
                '554 delivery error: .+?This user doesn\'t have .+? account',
                '540 5.7.1.+?Recipient address rejected.+?email account has been suspended',
                '550 5.1.1.+?Recipient address rejected: aol.com',
                '550 5.1.1.+?Recipient address rejected: user not found',
                '550 Requested action not taken: mailbox unavailable',
                'mailbox\. Local mailbox.+?is unavailable\: (user is terminated|user not found|account is disabled)',
            ],

            'inactive' => [

                '550 NOACTIVITY: Sorry, no recipient activity since',
                '550 Mailbox is frozen. See',
                '554 You have attempted to deliver to a bogus and forged e-mail address',
                '550 Mailbox .+? is locked due to inactivity for more than',
                '550-Mailbox .+? is locked due to inactivity for more than',
                '540 5.7.1.+?Recipient address rejected: Your emails has been returned because the intented recipient\'s email account has been suspended',
                '550 .+? Account blocked due to inactivity',
                '540 5.7.1 .+?: Recipient address rejected: Account locked by abuse team',
                '554 5.7.1 User .+? should log in to enable receiving the mail',
                '554 .+?: Relay access denied \(maybe you need to check mail via POP3 first',
                '550 Mailbox is blocked due to long-time inactivity',
                '552 .+? mail receiving disabled, rejecting',
            ],

            'relayerror' => [

                'host .+?said: 550 Relay not permitted',
                '\d54 \d.7.1 .+?: Relay access denied',
                '550 Relay access denied',
                '550 relay not permitted',
                '550 5.7.1 Unable to relay',
                '571 .+? prohibited. We do not relay',
                '554 Refused. Sending to remote addresses \(relaying\) is not allowed',
                '550 5.7.1 .+? Relaying denied',
                '550 5.7.64 TenantAttribution; Relay Access Denied',
                '550 5.7.54 SMTP; Unable to relay recipient in non-accepted domain',
            ],

            'remoteconfigerror' => [

                'unable to route: no mail hosts for domain',
                'Domain .+? does not accept mail \(nullMX\)',
            ],

            'invalidemail' => [

                'bad address syntax',
                'Bad destination mailbox address',
            ],
        ],

        self::TYPE_SOFT => [

            'temporaryerror' => [

                'refused to talk to me: 452 try later',
                '<.+?>:( delivery temporarily suspended:)? connect to .+?: Connection timed out',
                '<.+?>:( delivery temporarily suspended:)? connect to .+?: Connection refused',
                '<.+?>:( delivery temporarily suspended:)? connect to .+?: No route to host',
                '<.+?>:( delivery temporarily suspended:)? conversation with .+? timed out while receiving the initial server greeting',
                '451 4.2.1 mailbox temporarily disabled',

                // ???
                '4\d\d .+?: Recipient address rejected: User unknown in local recipient table',
                '4\d\d .+?: Recipient address rejected: User unknown in virtual mailbox table',
                '451 .+?: user unknown or mailbox full',
            ],

            'overquota' => [

                'MapiExceptionShutoffQuotaExceeded',
                '\d52 \d.2.2 Over quota',
                '\d52 \d.0.0 User mailbox is overquota',
                '\d5\d .+? account is full \(quota exceeded\)',
                '552 5.2.2 .*?Quota exceeded',
                '552-Requested mail action aborted: exceeded storage allocation',
                'permission denied. Command output: maildrop: maildir over quota',
                'Message rejected: this mailbox is over quota',
                'Message will exceed maximum mailbox size. Mail rejected',
                '550 Quota is over for this user',
                '550 Mailbox .+? is over quota, try again later',
                '550 5.2.2 .*?Over quota',
                '451 quota exceeded',
                '451 Mailbox quota exceeded',
                '550 Mailbox over quota',
                'maildir delivery failed: error writing message: Disk quota exceeded',
                'Your message to .+? was automatically rejected: Not enough disk space',
                '522 sorry, recipient mailbox is full',
                '550 Delivery error.Mailbox of .+? is FULL',
                '550 RCPT TO:.+? Mailbox disk quota exceeded',
                'This is a permanent error. The following address\(es\) failed: .+? Quota exceeded',
                '451 Account .+? out of quota. Try later',
                '550-Callout verification failed: 550 550 Recipient\'s mailbox is full, user account inactive',
                '450 Disk quota exceed for',
                'Your message cannot be delivered to the following recipients: Recipient address: .+? Reason: Over quota',
                'Quota exceeded \(mailbox for user is full\)',
                'Sorry, the user\'s maildir has overdrawn his diskspace quota',
                'Sorry, the user .+? over quota, please try again later',
                '552 Permanent failure, user is over quote',
                '452-4.2.2 The email account that you tried to reach is over quota',
                '552 5.2.2 Mailbox size limit exceeded',
                'error writing message: File too large',
                'temporary failure. Command output: maildrop: maildir over quota',
                ': <<< maildrop: maildir over quota',
                'generated by .+? mailbox is full',
                '450 4.2.2 .+?: user is overquota',
                '452 4.3.1 .+?Insufficient system storage',
                'This is a permanent error. The following address\(es\) failed:.+?Mailbox (is )?full',
                'Failed to deliver to.+?mailbox is full',
                'Failed to deliver to .+? LOCAL module\(account .+?\) reports: account is full \(quota exceeded\)',
			    '552-5.2.2 The email account that you tried to reach is over quota',

                'Quota exceeded',
                'user is over quota',
                'exceeds size limit',
                'user has full mailbox',
                'Mailbox disk quota exceeded',
                'over the allowed quota',
                'User mailbox exceeds allowed size',
                'does not have enough space',
                'mailbox is full',
                'Can\'t create output',
                'mailbox full',
                'File too large',
                'too many messages on this mailbox',
                'too many messages in this mailbox',
                'Not enough storage space',
                'Over quota',
                'over the maximum allowed number of messages',
                'Recipient exceeded email quota',
                'The user has not enough diskspace available',
                'Mailbox has exceeded the limit',
                'exceeded storage allocation',
                'Quota violation',
                '522_mailbox_full',
                'account is full',
                'incoming mailbox for user ',
                'message would exceed quota',
                'recipient exceeded dropfile size quota',
                'not able to receive any more mail',
                'user is invited to retry',
                'User account is overquota',
                'mailfolder is full',
                'exceeds allowed message count',
                'message is larger than the space available',
                'recipient storage full',
                'mailbox is full',
                'Mailbox has exceeded the limit',
                'The user\'s space has used up.',
                'user is over their quota',
                'exceed the quota for the mailbox',
                'exceed maximum allowed storage',
                'Inbox is full',
                'over quota',
                'maildir has overdrawn his diskspace quota',
                'disk full',
                'Quota exceed',
                'Storage quota reached',
                'user overdrawn his diskspace quota',
                'exceeded his/her quota',
                'quota for the mailbox',
                'The incoming mailbox for user',
                'exceeded the space quota',
                'mail box space not enough',
                'insufficient disk space',
                'over their disk quota',
                'Message would exceed ',
                'User is overquota',
                'Requested mailbox exceeds quota',
                'exceed mailbox quota',
                'over the storage quota',
                'over disk quota',
                'mailbox_quota_exceeded',
                'Status: 5.2.2',
                'over the maximum allowed mailbox size',
                'Delivery failed: Over quota',
                'exceed the quota for the mailbox',
                'errno=28',
            ],

            'blacklisted' => [

                '550 5.7.1 Mailbox unavailable. Your IP address .+? is blacklisted using',
                '554 5.7.1 Service unavailable; Client host .+? blocked using',

                // common spamlists
                '(s5h|barracudacentral|spamcop|blacklist.woody|bogons.cymru|abuseat|abuse|wpbl|uceprotect|dnsbl.dronebl|'.
                    'sorbs|spfbl|duinv.aupads|spamrats|backscatterer|dnsbl.manitu|orvedb.aupads|spamhaus|bl.gweep|psbl.surriel|'.
                    'relays.nether|dnsbl.anonmails|spambot.bls.digibase|spamrbl.imp.ch|ubl.lashback|ubl.unsubscore|virus.rbl|'.
                    'wormrbl.imp|z.mailspike)\.(net|com|info|ch|org|ca|jp|de)',

                // gmail ([\d\.-]+ => 421-4.7.28)
                'Our system has detected an unusual rate of [\d\.-]+ unsolicited mail originating from your IP address. To protect our [\d\.-]+ users from spam',

                // from last problem 30 oct 2020
                'Client host \[[\d\.]\]+ blocked using urbl.hostedemail.com',
            ],

            'blockedcontent' => [

                '<.+?>: host .+? said: 550 Message refused by spam filter',
                '<.+?>: host .+? refused to talk to me: 554 .+? A problem occurred',
                '<.+?>: host .+? refused to talk to me: 553 Mail from .+? not allowed',
                '<.+?>: host .+? said: 550.+?Message rejected as spam by Content Filtering',
                '<.+?>: host .+? said: 550-sender IP-address .+? locally blacklisted because of too much spam',
                '<.+?>: lost connection with .+?while receiving the initial server greeting',
                '<.+?>: delivery temporarily suspended: lost connection with .+?while receiving the initial server greeting',
                '<.+?>: host .+? said: 554 Service unavailable; Client host .+? blocked using Barracuda Reputation',
                '_is_blocked.For assistance forward this email to abuse_rbl@abuse-att.net',
                '550 5.7.1 Requested action not taken: message refused',
                '554 5.7.1 Mail appears to be unsolicited',
                '500 Message rejected',
                '<.+?>: host .+? said: 550 High probability of spam',
                '<.+?>: host .+? said: 550 5.7.1 Refused by local policy. No SPAM please',
                '<.+?>: host .+? said: 554 5.7.1 This email from IP .+? has been rejected. The email message was detected as spam',
                '<.+?>: host .+? said: 550 Addresses failed:.+?Blacklisted',
                '550 5.7.1 Message rejected.',
                '550 5.7.1 Access denied',
                '550-Your message was rejected by this system and was not delivered',
                '550 5.7.1 This message is blocked due to security reason',
                '5.7.1 Message rejected by UNICOMP mail system',
                '550 Administrative prohibition - .+? banned',
                '530 5.7.57 SMTP; Client was not authenticated to send anonymous mail',
                'Your e-mail was rejected for policy reasons on this gateway',
                '550 Protocol violation',
                'Blacklisted',
                'is refused. See http://spamblock.outblaze.com',
                'Mail appears to be unsolicited',
                'rejected for policy reasons',
                'Spam rejected',
                'Error: content rejected',
                'Denied by policy',
                'Blocked for spam',
                'Blocked for abuse',
                'considered unsolicited bulk e-mail',
                'listed in multi.surbl.org',
                'black listed url host',
                'this message scored ',
                'on spam scale',
                'message filtered',
                'rejected as bulk',
                'message content rejected',
                'Mail From IP Banned',
                'Connection refused due to abuse',
                'mail server is currently blocked',
                'Spam origin',
                'extremely high on spam scale',
                'is not accepting mail from this sender',
                'spamblock',
                'appears to be spam',
                'message looks like spam',
                'message looks like a spam',
                'high spam probability',
                'email is considered spam',
                'Spam detected',
                'Message identified as SPAM',
                'blocked because it contains FortiGuard - AntiSpam blocking URL',
                ' This message has been blocked because it contains FortiSpamshield blocking URL',
                'Sender is on domain\'s blacklist',
                '5.7.1 Message cannot be accepted, spam rejection',
                'Mail contained a URL rejected by SURBL',
                'This message has been flagged as spam',
                '550 POSSIBLE SPAM',
                'headers consistent with spam',
                '5.7.1 Content-Policy reject',
                'rejected by an anti-spam',
                'rejected by anti-spam',
                'is on RBL list',
                'sender denied',
                'Your message was rejected because it appears to be part of a spam bomb',
                'it is spam',
                '5.7.1 bulkmail',
                'Message detected as spam',
                '5.7.1 Blocked',
                'identified SPAM',
                'Error: SPAM',
                'message is banned',
                'junk mail',
                'bulk mail rejected',
                'SPAM not accepted',
                'rejected By DCC',
                'Spam Detector',
                '5.7.1 Message rejected',
                '5.7.1 Rejected as SPAM',
                'Message rejected due to the attachment filtering policy',
                'Message rejected due to content restrictions',
                'Spam is not allowed',
                'Blocked by policy',
                'content filter',
                'spam filter',
                'filter rejection',
                'rejected by spam-filter',
                'Forbidden for policy reasons',
                'looked like SPAM',
                'Message blocked',
                'not delivered for policy reasons',
                'high on spam',
                '5.7.1 Rejected - listed at ',
                '550 This message scored ',
                'Blocked by SPAM',
                'This message has been blocked',
                'SURBL filtered by ',
                'message classified as bulk',
                'mail rejected for spam',
                'message that you send was considered spam',
                'message that you sent was considered spam',
                '550 Spam',
                'Sorry, message looks lik',
                'email has been identified as SPAM',
                'possible spam',
                '550 Content Rejected',
                'Message not allowed by spam',
                'has been quarantined',
                'blocked as spam',
                'DNSBL:To request removal of',
                'won\'t accept this email',
                'Rejected by filter processing',
                'marked by Telerama as SPAM',
                'triggered a spam block',
                'Message classified as spam by Bogofilter',
                'http://postmaster.info.aol.com/errors/421dynt1.html',
                'Spam limit has been reached',
                'Your email has been automatically rejected',
                'message from policy patrol email filtering',
                'blocked by filter rules',
                'Mail rejected by Windows Live Hotmail for policy reasons',
                '554 5.7.1 .+?: Sender address rejected: LIST_ACCESS_FROM',
				'554 5.7.1 Your mail could not be delivered because the recipient is only accepting mail from specific email addresses|'.
				'550 5.7.1 Policy rejection on the target address',
                '550 Rule imposed mailbox access for',
                'Message cannot be accepted, content filter rejection',
                'Message Denied: Restricted attachment',
                'has exceeded maximum attachment count limit',
                'Message held for human verification',
                'message held before permitting delivery',
                'envelope sender is in my badmailfrom',
                'HTML tag unacceptable',
                'not accepting mail with attachments or embedded images',
                'message contains potential spam',
                'You have been blocked by the recipient',
                'Message contains unacceptable attachment',
                'This message does not comply with required standards',
                'Message rejected because of unacceptable content',
                '554 Transaction failed',
                '5.7.1 reject content',
                '5.7.1 URL/Phone Number Filter',
                'they are not accepting mail',
                'not accepting mail with attachments or embedded images',
                'invalid message content',
                '550 Rejected',
                'Message rejected: Conversion failure',
                'no longer accepts messages with',
                'One of the words in the message is blocked',
            ],

            'remoteconfigerror' => [

                '550 Sender IP reverse lookup rejected',
                'connect to .+?:25: Connection timed out',
                'This is a permanent error. The following address\(es\) failed: .+? local delivery failed: retry timeout exceeded',
                '474 .+? no DNS A-data returned',
                '554 5.4.14 Hop count exceeded - possible mail loop',
                'routing loop detected',
                ': mail for .+? loops back to myself',
            ],
        ],

        self::TYPE_IGNORE => [

            'autoanswer' => [

                'This is an automatically generated Delivery Status Notification. THIS IS A WARNING MESSAGE ONLY. YOU DO NOT NEED TO RESEND YOUR MESSAGE.',
                'This is a warning message only',
                'I am on vacation or otherwise unable to read my email',
                'I am unavailable to read your message at this time.',
                'I am away until ',
                'when I return to the office',
                'I am out of town',
                'I will be on vacation ',
                'I shall be out of office ',
                'I will be away ',
                'I am away from ',
                'I will be out of the office ',
                'I am on sabbatical',
                'will not be responding promptly',
                'I am out of the country',
                'I am currently out of office',
                'I am currently out of the office',
                'I am on vacation ',
                'on personal leave',
                'unavailable to read your message',
                'away from the office',
                'YOU DO NOT NEED TO RESEND YOUR MESSAGE',
                'I am unavailable to read your message',
                'Thank you for recent email',
                'Thank you for your email',
                'This is an auto respond',
                'Thanks for contacting ',
                'Thank you for contacting ',
                'Thank you for your e-mail',
                'out of the office',
                'This is an autoreply',
                'Your message has been received',
                'has received your email',
                'have received your email',
                'have received your mail',
                'have received your message',
                'Thanks for contacting me',
                'I will be out on vacation',
                'Thank you For mailing',
                'I\'m on vacation',
                'I have got your mail',
                'I am currently away',
                'Thanks for the mail',
                'Thanks for inquiring',
                'Thank you for e mail',
                'Your message has been received',
                'Thank you for contacting',
                'Thank you for taking time to contact',
                'automatic response',
                'I will read your message',
                'read your message as soon',
                'I will be on leave',
                'get back to you as soon',
                'very much for your inquiry',
                'for your inquiry',
                'Thank you for your mail',
                'Thanks for your mail',
                'Thank you for your message',
                'thank you for e-mail',
                'will be absent from',
                'not available right now',
                'This is an automated reply',
                'I will reply shortly',
                'out of office',
                'This is an autoresponder',
                'Thanks for your email',
                'currently on holiday',
                'on maternity leave',
                'We have received your e-mail',
                'We have received your mail',
                'will try to reply',
                'is on holiday',
                'currently on vacation',
                'Thank you for your recent e-mail',
                'Thank you for your recent email',
                'Thank you for your recent mail',
                'I got your email',
                'Thank you for your communiqu',
                'respond to your email as soon as possible',
                'away right now',
                'will get back to you soon',
                'Thanks for writing',
                'reply as soon as possible',
                'reply you soon',
                'AutoReply',
                'Auto Response',
                'Thanks for writing',
                'I will be away',
                'On Vacation',
                'Out of Office',
                'away from e-mail',
                'thank you for your enquiry',
                'thanks for the email',
                'after more than 72 hours',
                'after more than 48 hours',
                'after more than 24 hours',
            ],
        ],
    ];

    public function __construct(ILogService $logService, array $excludeEmails = [])
    {
        $this->logger = $logService->getLogger(self::class);
        $this->excludeEmails = $excludeEmails;
        $this->prepareBounceRules();
    }

    public function classifyBounce(string $emailHeaders, string $emailBody): array
    {
        $date =
            preg_match('!^Date: (.+)!mi', $emailHeaders, $date)
                ? date('Y-m-d H:i:s', strtotime($date[1]))
                : 'can\'t_get_date';
        $subject = $this->getSubject($emailHeaders);
        $fromEmail = $this->getEmailFromHeaders('From', $emailHeaders);

        if (
            preg_match('!^.+?Feedback Loop.*!is', $subject, $fbl) // is abuse report
            && preg_match('!Content-Type: message/feedback-report\s+?feedback-type: abuse(?<innerLetter>.+)!is', $emailBody, $m)
            && preg_match('!^To: .+?<(?<email>.+?)>!mi', $m['innerLetter'], $to)
        ) {
            return $this->logAndReturn([$to['email']], self::TYPE_SOFT, 'fbl', $fbl[0]);
        }

        if (preg_match('!^\s*?Report Domain:\s*?(?<domain>[^\s]+?);?\s*?Submitter:\s*?(?<submitter>[^\s]+);?\s*?!is', $subject, $m)) {
            $submitter = trim($m['submitter'], ' ;');
            return $this->logAndReturn([$fromEmail], self::TYPE_IGNORE, 'dmarc_report', "dmarc report for {$m['domain']} from {$submitter}");
        }

        if (preg_match('!^reading confirmation receipt!i', $subject)) {
            return $this->logAndReturn([$fromEmail], self::TYPE_IGNORE, 'read_confirmation');
        }

        if (
            preg_match('!^x-autoreply: (?<email>(<pfx>.+?)@(?<domain>.+))!mi', $emailHeaders, $xAutoReply)
            && preg_match('!^reply-to: (?<email>.+)!mi', $emailHeaders, $replyTo)
            && ($replyTo['email'] == "{$xAutoReply['pfx']}.autoreply@{$xAutoReply['domain']}")
        ) {
            return $this->logAndReturn([$xAutoReply['email']], self::TYPE_IGNORE, 'autoreply');
        }

        if (
            preg_match('!^X-Autogenerated: Reply!mi', $emailHeaders)
            || preg_match('!^Auto-submitted: auto-generated!mi', $emailHeaders)
            || (preg_match('!^X-AutoReply: yes!mi', $emailHeaders)
                && (preg_match('!^Auto-Submitted: auto-replied!mi', $emailHeaders)
                    || preg_match('!^X-AutoReply-From: (?<email>.+)!mi', $emailHeaders, $xAutoReplyFrom)))
        ) {
            $from = $xAutoReplyFrom ? $xAutoReplyFrom['email'] : $fromEmail;
            return $this->logAndReturn([$from], self::TYPE_IGNORE, 'autoreply');
        }

        if (preg_match('!^Return-Path: <auto-answer@i.ua>!mi', $emailHeaders)) {
            return $this->logAndReturn([$fromEmail], self::TYPE_IGNORE, 'autoreply');
        }

        $emails = $this->extractEmails($emailBody);
        if (empty($emails) && $fromEmail && !in_array($fromEmail, $this->excludeEmails)) {
            $emails[] = $fromEmail;
        }

        foreach ($this->bounceRules as $bounceType => $categories) {
            foreach ($categories as $categoryName => $patternList) {
                foreach ($patternList as $pattern) {
                    $result = preg_match($pattern, $emailBody, $m);
                    if ($result) {
                        return $this->logAndReturn($emails, $bounceType, $categoryName, $pattern, $m);
                    }
                    if ($result === false) {
                        $this->logger->error("Regexp error in '{$pattern}'");
                    }
                }
            }
        }

        $this->logger->debug('Unable to classify bounce', [
            'date'    => $date,
            'from'    => $fromEmail,
            'subject' => $subject,
            'body'    => $emailBody,
        ]);

        return [
            'emails'     => [$fromEmail],
            'bounceType' => IBounceClassifier::TYPE_UNKNOWN,
        ];
    }

    protected function logAndReturn($emails, $bounceType, $categoryName, $pattern = false, $matches = false)
    {
        $result = [
            'emails'     => json_encode($emails),
            'bounceType' => self::BOUNCE_TYPE_MNEMONICS[$bounceType],
            'category'   => $categoryName,
        ];

        if ($pattern) {
            $result['pattern'] = $pattern;
        }

        if ($matches) {
            $result['reason'] = preg_replace('!\s+!', ' ', $matches[0]);
        }

        $this->logger->info('Bounce classified', $result);

        $result['emails'] = $emails;
        $result['bounceType'] = $bounceType;

        return $result;
    }

    private function prepareBounceRules()
    {
        if ($this->bounceRules === null) {
            $this->bounceRules = [];
            foreach ($this->sourceRules as $bounceType => $categories) {
                foreach ($categories as $categoryName => $patternList) {
                    foreach ($patternList as $pattern) {
                        $pattern = preg_replace('!\s+!', '\s+', $pattern);
                        $pattern = preg_replace('!\.[^+*?\]({\\\]!', '\.', $pattern);
                        $this->bounceRules[$bounceType][$categoryName][] = "!{$pattern}!is";
                    }
                }
            }
        }
    }

    protected function extractEmails($emailBody)
    {
        $res = [];
        $emailTypes = ['To', 'Final-Recipient', 'Original-Recipient'];
        foreach ($emailTypes as $emailType) {
            $email = $this->getEmailFromHeaders($emailType, $emailBody);
            if ($email) {
                $res[$email] = null;
            }
        }
        return array_diff(array_keys($res), $this->excludeEmails);
    }

    public function getSubject(string $headers): string
    {
        $subject = '';
        if (preg_match('!^(.+?\r?\n)?Subject: (?<subject>.+?)(?=(\r?\n[^\r\n]+:|\r?\n\r?\n))!is', $headers, $m)) {
            foreach (imap_mime_header_decode($m['subject']) as $s) {
                $subject .= $s->text;
            }
        }

        return $subject;
    }

    public function getEmailFromHeaders(string $type, string $headers): ?string
    {
        if (preg_match("!^{$type}: .*?<?(?<email>([a-z\d_]|[a-z\d_][a-z\d._\-]*[a-z\d_\-]{1})@([a-z\d]{1}[a-z\d\-]*\.)+[a-z]{2,})>?!mi", $headers, $m)) {
            return $m['email'];
        }

        return false;
    }
}
