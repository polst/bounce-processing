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
                '550 5.1.10 RESOLVER.ADR.RecipientNotFound',
                'Message was not accepted -- invalid mailbox. Local mailbox [^\s]+ is unavailable: user not found',
                'Message was not accepted -- invalid mailbox. Local mailbox [^\s]+ is unavailable: account is disabled',
                'Message was not accepted -- invalid mailbox. Local mailbox [^\s]+ is unavailable: user is terminated',
                'LOCAL module\(account [^\s]+\) reports: mail receiving disabled',
                'This is a permanent error. The following address\(es\) failed: [^\s]+ Unknown user',
                'This is a permanent error. The following address\(es\) failed: [^\s]+ Unrouteable address',
                '5.1.0 - Unknown address error 553-\'Invalid/inactive user',
                '550-5.1.1 The email account that you tried to reach does not exist',
                '550(\d|-)5.1.1 User unknown',
                '550(\d|-)5.1.1 Unknown recipient',
                '550 "Unknown user for this domain"',
                'Podane konto jest zablokowane administracyjnie lub nieaktywne / This account is disabled or not yet active',
                'Podane konto nie istnieje / No mailbox here by that name',
                'This user doesn\'t have a [^\s]+ e-mailaccount',
                'This account has been disabled or discontinued',
                'The ESMTP Mail System program [^\s]+: unknown user:',
                '550 5.7.1 [^\s]+: Recipient address rejected: Account closed',
                '55\d:? Recipient address rejected: User unknown',
                '5\d\d [^\s]+: Recipient address rejected: User unknown in local recipient table',
                '5\d\d [^\s]+: Recipient address rejected: User unknown in virtual mailbox table',
                '540 5.7.1 [^\s]+ Recipient address rejected: Account deleted by user',
                '550 5.1.1 Recipient address rejected: User unknown',
                '55\d(\s+|-)5\.\d\.\d [^\s]+: Recipient address rejected',
                '550 5.1.1 [^\s]+ Recipient address rejected: aol.com',
                '550 5.1.1 [^\s]+ Recipient address rejected: user not found',
                '540 5.7.1 [^\s]+: recipient address rejected: Blocked',
                '550 5.5.0 Requested action not taken: mailbox unavailable',
                '550 [^\s]+ unknown user account',
                '550 5.1.1 unknown or illegal alias',
                '550 5.7.1 No such user',
                '550 Requested action not taken: mailbox unavailable',
                '551 [^\s]+: user unknown or mailbox full',
                '504 Mailbox is disabled',
                '550 5.7.1 Message rejected \(no valid recipients\)',
                '550 5.1.1 Not our Customer',
                '550: Requested action not taken: mailbox unavailable',
                '550 5.1.1 [^\s]+ recipient rejected \(mailbox locked\)',
                '550 5.1.1 [^\s]+ Recipient Rejected',
                '550 5.1.1 Account not found \/ Nie ma takiego konta',
                '550 5.1.1 [^\s]+: user does not exist',
                '550 5.1.1 [^\s]+: Email address could not be found, or was misspelled',
                '554 Mailaddress is administratively disabled',
                '550 No such person at this address',
                '550 "User inactive"',
                '550-Unknown/invalid recipient',
                '550 Recipient Rejected: No account by that name here',
                '550-e-mail address [^\s]+ doesn\'t exist or blocked or 550 mailbox is full',
                '550-5.2.1 The email account that you tried to reach is disabled',
                '554 Invalid mailbox',
                'Your message wasn\'t delivered to [^\s]+ because the address couldn\'t be found',
                '550 5.2.1 The email account that you tried to reach is disabled',
                '553 5.3.0 [^\s]+ No such user',
                '5\d\d No such user',
                '550 Mailbox unavailable',
                '550 User not found',
                '550 5.1.1 Bad destination mailbox addres',
                '550 Unknown user',
                '550 5.7.1 [^\s]+... unknown user',
                '550 "Unknown User"',
                '55\d 5.\d.\d [^\s]+ User unknown',
                '550 RCPT TO:<[^\s]+> User unknown',
                '55\d [^\s]+ User unknown',
                '55\d [^\s]+ Recipient unknown',
                '550 [^\s]+ mail receiving disabled',
                '5\d\d (5.\d.\d )?sorry, no mailbox here by that name',
                '5\d\d 5.\d.\d [^\s]+ : sorry, no mailbox here by that name',
                '554 5.2.1 No such user yet',
                '550 5.1.1 [^\s]+... User unknown',
                '550 #5.1.0 Address rejected',
                '550 Unrouteable address',
                '550 Invalid Recipient',
                '550 5.2.1 The email account that you tried to reach is disabled',
                '550-5.2.1 Mailbox unavailable',
                '550 5.1.1 [^\s]+ Mailbox is not available',
                '550 5.0.0 [^\s]+ This is user have no mail',
                '550 Recipient rejected: User [^\s]+ not found',
                '550 .*?No Such User',
                '550 No such recipient',
                '550 [^\s]+ user not found',
                '50\d Bad address syntax',
                '550 Failed to deliver to address',
                '550 rejected: Unknown recipient',
                '550 [^\s]+ Mailbox does not exist',
                '550 5.1.1 [^\s]+? Recipient does not exist',
                '550-5.2.1 The email account that you tried to reach is disabled',
                '554 delivery error: [\d\.]* Sorry, your message to [^\s]+ cannot be delivered. This mailbox is disabled',
                '550 5.1.1 .*?Recipient not found',
                '550 "Error 60: No mailbox',
                '550-Invalid recipient',
                '554 5.7.1 User [^\s]+ cannot receive email',
                '554 delivery error: [^\s]+ This user doesn\'t have [^\s]+ account',
                '550 Requested action not taken: mailbox unavailable',
                'mailbox\. Local mailbox [^\s]+ is unavailable\: (user is terminated|user not found|account is disabled)',
                '552 \d Requested mail action aborted, mailbox not found', // yahoo
                '550 RCPT TO: [^\s]+ SMTP delivery not allowed',
                '550 5.1.1 [^\s]+... User is unknown',
                '\(expanded from [^\s]+\): unknown user:',
                '550 Address unknown',
                '550 5.1.1 [^\s]+ is not a valid mailbox',
                '550 Administrative prohibition',
                '550 [^\s]+: invalid address',
                '553 Recipient [^\s]+? does not exist',
                '554 delivery error: dd This user doesn\'t have a [^\s]+ account',
                '554 delivery error: dd Requested mail action aborted, mailbox invalid',
                '553 Invalid user',
                '[^\s]+: Sorry, no mailbox here by that name. \(#5.1.1\)',
                '550 Command RCPT User [^\s]+ not OK',
                'This is a permanent error. The following address\(es\) failed: [^\s]+ retry time not reached for any host after a long failure period',
                '550 failed: User does not exist',
                '550 Mailbox not found',
                '553 Invalid/inactive user',
                '554 Invalid recipient',
                '[^\s]+: user unknown. Command output: Invalid user specified',
                '5.1.1 Diagnostic-Code: x-unix; user unknown',
                '550 5.2.1 Mailbox not available',
                '5.7.1 [^\s]+... Recipient not found',
                '550 no mailbox by that name is currently available',
                '550 5.2.0 mailbox unavailable',
                '550 5.7.1 Recipient rejected \(R4\)',
                '550 No such email address',
                'The message is attached below. The remote mail system said: Invalid Recipient',
                'Sorry, no mailbox here by that name. vpopmail \(#5.1.1\)',
                '550 5.7.0 [^\s]+... this address does not exist - visit our web site',
                '550 5.1.1 [a-z\d]+ Siamo spiacenti, non esiste nessun utente con questo nome',
                '550 5.1.1 [^\s]+ sorry, no mailbox here by that name',
                'Delivery to the following recipient failed permanently:',
                '550 5.1.1 Adresse d au moins un destinataire invalide. Invalid recipient',
                'The remote mail system said: RCPT TO:[^\s]+ SMTP delivery not allowed',
                '422 invalid user name\!',
                'This is a permanent error. The following address\(es\) failed: [^\s]+ local delivery failed: retry timeout exceeded',
                '550 5.1.1 RCP-P1.+?Recipient address does not exist',
                '<[^\s]+>: user does not exist',
                '550 5.1.1 [^\s]+ Recipient address rejected: User unknown in virtual mailbox table',
                '550 Requested action not taken: mailbox unavailable',
                '550 Unknown destination address',
                // invalid domain of user email, not our MTA
                'Host or domain name not found. Name service error for name',
                '550 <[^\s]+>, destin. sconosciuto',
                'Your message wasn\'t delivered because the address [^\s]+ couldn\'t be found',
                '550 I cannot deliver mail for',
                '<[^\s]+>: This user doesn\'t have a yahoo.com account',
                '5.1.1 Diagnostic-Code: X-Postfix; unknown user:',
                '550 [^\s]+ 5.4.1 [^\s]+: Recipient address rejected: Access denied',
                '550 SITEGROUND: No Such mailbox here',
                '521 No Redirect Entry for this address',
                '550 5.1.1 Mail Refused - Address <[^\s]+> Recipient Unknown',
                '550 5.1.1 [^\s]+ Sorry, no user here by that name',
                '550 Questo indirizzo non esiste',
                '553 Invalid recipient',
                '554 no valid recipients, bye',
                '554 <[^\s]+>: Messaggio rifiutato dal sistema. Indirizzo destinatario sconosciuto o non abilitato alla ricezione di posta non certificata',
                '550 mailbox [^\s]+ unavailable',
                'This user doesn\'t have a ymail.com account',
                '5.1.1 <[^\s]+> is not a valid mailbox',
            ],

            'inactive' => [

                '550 NOACTIVITY: Sorry, no recipient activity since',
                '550 Mailbox is frozen. See',
                '554 You have attempted to deliver to a bogus and forged e-mail address',
                '550 Mailbox [^\s]+ is locked due to inactivity for more than',
                '550-Mailbox [^\s]+ is locked due to inactivity for more than',
                '540 5.7.1 [^\s]+ Recipient address rejected: Your emails has been returned because the intented recipient\'s email account has been suspended',
                '550 [^\s]+ Account blocked due to inactivity',
                '55\d:? Recipient address rejected: Inactive user',
                '540 5.7.1 [^\s]+ recipient address rejected: Inactive',
                '540 5.7.1 [^\s]+ Recipient address rejected: Account locked by abuse team',
                '540 5.7.1 [^\s]+ Recipient address rejected [^\s]+ email account has been suspended',
                '554 5.7.1 User [^\s]+ should log in to enable receiving the mail',
                '554 [^\s]+: Relay access denied \(maybe you need to check mail via POP3 first',
                '550 Mailbox is blocked due to long-time inactivity',
                '552 [^\s]+ mail receiving disabled, rejecting',
                '551 [^\s]+ is a deactivated mailbox',
                '550 RCPT TO:[^\s]+ Mailbox disabled',
                '550 user mailbox is inactive',
                'vdelivermail: account is locked email bounced',
                '550 Recipient mailbox was disabled',
                '552 [^\s]+ is a disabled mailbox',
                '550 Delivery is not allowed to this address',
                '450 this recipient is not allowed',
                '550 5.1.1 [^\s]+ recipient disabled',
                '550 5.2.1 <[^\s]+> Account administratively disabled',
                '5.2.1 Diagnostic-Code: x-unix; This address no longer accepts mail',
                'Sorry, your message to [^\s]+ cannot be delivered. This mailbox is disabled',
                'Receiver do\'nt want your email. Are You shure you have sent your Mail to the right adress',
            ],

            'relayerror' => [

                'host [^\s]+ said: 550 Relay not permitted',
                '\d54 \d.7.1 [^\s]+: Relay access denied',
                '550 relaying denied',
                '513 Relaying denied',
                '551 5.7.1 relaying denied',
                '550 Relay access denied',
                '550 relay not permitted',
                '550 5.7.1 Unable to relay',
                '571 [^\s]+ prohibited. We do not relay',
                '554 Refused. Sending to remote addresses \(relaying\) is not allowed',
                '550 5.7.1 [^\s]+ Relaying denied',
                '550 5.7.64 TenantAttribution; Relay Access Denied',
                '550 5.7.54 SMTP; Unable to relay recipient in non-accepted domain',
                '503 This mail server requires authentication when attempting to send to a non-local e-mail address',
                '530 Relaying not allowed',
                '558 Relaying denied: domain not valid',
                '550 RCPT TO:[^\s]+ Relaying not allowed - please use SMTP AUTH',
                '550 5.7.1 [^\s]+: Relay access denied',
                '554 [^\s]+: Relay access denied',
                '554 Relay access denied',
                '501 This system is not configured to relay mail to',
                '550 5.7.1 <[^\s]+>... we do not relay',
                '553 sorry, relay of mail is not allowed',
            ],

            'remoteconfigerror' => [

                'unable to route: no mail hosts for domain',
                'Domain [^\s]+ does not accept mail \(nullMX\)',
                '550 We don\'t handle mail for',
                '550 5.1.0 [a-z\d]+ dominio non valido / invalid domain',
                '553 sorry, that domain isn\'t in my list of allowed rcpthosts',
                '553-5.7.1 sorry, that domain isn\'t in my list of allowed rcpthosts',
                '550 RCPT address has non-existant domain [^\s]+',
                '550 Domain [^\s]+ has outgoing email disabled',
                '550 sorry, this mailbox is currently disabled, try again',
            ],

            'invalidemail' => [
                'bad address syntax',
                'Bad destination mailbox address',
                '501 Invalid Address',
            ],
        ],

        self::TYPE_SOFT => [

            'temporaryerror' => [

                'refused to talk to me: 452 try later',
                'refused to talk to me: 421 [^\s]+ Service Unavailable',
                'refused to talk to me: 421 4.\d.\d Service not available',
                'refused to talk to me: 421 [^\s]+ ESMTP - Too many connections',
                'refused to talk to me: 421 [^\s]+ Service refused, please try later',
                '450 4.2.2 [^\s]+... temporary failure; please retry later',
                'Can\'t open mailbox for [^\s]+. Temporary error',
                '421 [^\s]+ ESMTP server temporari?ly not available',
                '4.3.0 Diagnostic-Code: X-Postfix; alias database unavailable',

                '<[^\s]+>:( delivery temporarily suspended:)? connect to [^\s]+: Connection timed out',
                '<[^\s]+>:( delivery temporarily suspended:)? connect to [^\s]+: Connection refused',
                '<[^\s]+>:( delivery temporarily suspended:)? connect to [^\s]+: No route to host',
                '<[^\s]+>:( delivery temporarily suspended:)? conversation with [^\s]+ timed out while receiving the initial server greeting',
                'delivery temporarily suspended: lost connection with [^\s]+ while sending end of data',
                'conversation with [^\s]+ timed out while sending end of data',
                'lost connection with [^\s]+ while performing the (HE|EH)LO handshake',
                'lost connection with [^\s]+ while sending RCPT TO',
                '451 4.2.1 mailbox temporarily disabled',
                '452 4.1.1 [^\s]+ Account temporarily unavailable. Try again later',
                'temporary failure. Command output:',
                'connect to [^\s]+:25: Connection timed out',
                '501 5.5.4 Unrecognized parameter',
                '4.4.1 Diagnostic-Code: X-Postfix; connect to [^\s]+:25: Network is unreachable',
                '554 [^\s]+ ESMTP not accepting connections',
                '550 Not allowed to send from that country',
                '550 Recipient Rejected: Temporarily inactive',
                '500 Syntax error, command unrecognized',
                '421 Too many concurrent SMTP connections',
                '421 Requested action aborted: local error in processing',
                '451 4.3.5 <[^\s]+>: Sender address rejected: Server configuration problem',
                'I\'m afraid I wasn\'t able to deliver the following message. This is a permanent error; I\'ve given up. Sorry it didn\'t work out',
                'Requested mail action aborted I\'m not going to try again; this message has been in the queue too long',
                '421 4.3.2 Service shutting down, Error writing to mail file: Spazio esaurito sul device at',

                // dns errors (!?)
                '553 5.1.8 [^\s]+... Domain of sender address [^\s]+ does not exist',

                // aol
                'refused to talk to me: 421 4.7.1 : \(DYN:T1\)',
                
                // google
                '550-5.2.1 The user you are trying to contact is receiving mail at a rate that',

                // libero.it
                '421 [^\s]+ bizsmtp Too many connections, slow down',
                '421 [^\s]+ [^\s]+ Too many connections, slow down',
                '451 too many invalid recipients',
                '451 [^\s]+ [^\s]+ too many invalid recipients',

                // alice.it
                '421 <[^\s]+> Service not available - too busy',

                // facebook
                '421 4.7.1 RCP-T4.+?Recipient account is unavailable',
                '421 4.3.5 [^\s]+ technical difficulties',

                // ???
                '4\d\d [^\s]+: Recipient address rejected: User unknown in local recipient table',
                '4\d\d [^\s]+: Recipient address rejected: User unknown in virtual mailbox table',
                '451 [^\s]+: user unknown or mailbox full',
            ],

            'blacklisted' => [

                '550 5.7.1 Mailbox unavailable. Your IP address [^\s]+ is blacklisted using [^\s]+',
                '554 5.7.1 Service unavailable; Client host [^\s]+ blocked using [^\s]+',

                // common spamlists
                '(s5h|barracudacentral|spamcop|blacklist.woody|bogons.cymru|abuseat|abuse|wpbl|uceprotect|dnsbl.dronebl|'.
                    'sorbs|spfbl|duinv.aupads|spamrats|backscatterer|dnsbl.manitu|orvedb.aupads|spamhaus|bl.gweep|psbl.surriel|'.
                    'relays.nether|dnsbl.anonmails|spambot.bls.digibase|spamrbl.imp.ch|ubl.lashback|ubl.unsubscore|virus.rbl|'.
                    'wormrbl.imp|z.mailspike|csi.cloudmark|urbl.hostedemail)\.(net|com|info|ch|org|ca|jp|de)',

                '553 5.3.0 [^\s]+ DNSBL:ATTRBL 521',
                '554 .+? IP: [\d\.]+, You are not allowed to send (us )?mail',
                'Mail Refused - IP Address [^\s]+ Blacklisted',
                '554 5.7.1 ACL dns_rbl; Client host [^\s]+ blocked using [^\s]+ Senderscore',

                // mail.com
                '554-No SMTP service 554-IP address is black listed',
            ],

            'blacklisted:gmail' => [

                // [\d\.-]+ => 421-4.7.28
                'Our system has detected an unusual rate of [\d\.-]+ unsolicited mail originating from your IP address. To protect our [\d\.-]+ users from spam',
                'Our system has detected that this message is 550-5.7.1 likely unsolicited mail. To reduce the amount of spam sent to Gmail, 550-5.7.1 this message has been blocked',
            ],

            'blacklisted:hotmail' => [

                '421 RP-001 .+? Unfortunately, some messages from [\d\.]+ weren\'t sent. Please try again. We have limits for how many messages can be sent per hour and per day',
                '550 (OU|SC)-001 .+? Unfortunately, messages from [\d\.]+ weren\'t sent. Please contact your Internet service provider since part of their network is on our block list',
                '550 5.7.1 Unfortunately, messages from [^\s]+ weren\'t sent. Please contact your Internet service provider since part of their network is on our block list',
            ],

            'blacklisted:yahoo' => [

                '421 4.7.1 \[TS03\] All messages from [\d\.]+ will be permanently deferred',
                '553 5.7.2 \[TSS09\] All messages from [\d\.]+ will be permanently deferred',
                '421 4.7.0 \[TS01\] Messages from [\d\.]+ temporarily deferred',
                '553 5.7.1 \[[a-z\d]{4,}\] Connections will not be accepted from [\d\.]+, because the ip is in Spamhaus\'s list',
            ],

            'blacklisted:tiscali.it' => [

                '421 .+? ESMTP - Too many invalid recipients from this IP',
                '554 .+? ESMTP - Too much Spam from this IP',
            ],

            'blacklisted:alice.it' => [

                '554 Too many unknown RCPT TO addresses from host',
                '550 mail not accepted from blacklisted IP address',
            ],

            'blockedcontent' => [

                '550 Message refused by spam filter',
                '554 [^\s]+ A problem occurred',
                '553 Mail from [^\s]+ not allowed',
                '550 [^\s]+ Message rejected as spam by Content Filtering',
                '550-sender IP-address [^\s]+ locally blacklisted because of too much spam',
                '<[^\s]+>: lost connection with [^\s]+ while receiving the initial server greeting',
                '<[^\s]+>: delivery temporarily suspended: lost connection with [^\s]+ while receiving the initial server greeting',
                '554 Service unavailable; Client host [^\s]+ blocked using Barracuda Reputation',
                '_is_blocked.For assistance forward this email to abuse_rbl@abuse-att.net',
                '550 5.7.1 Requested action not taken: message refused',
                '554 5.7.1 Mail appears to be unsolicited',
                '500 Message rejected',
                '550 High probability of spam',
                '550 5.7.1 Refused by local policy. No SPAM please',
                '554 5.7.1 This email from IP [^\s]+ has been rejected. The email message was detected as spam',
                '550 Addresses failed: [^\s]+ Blacklisted',
                '550 5.7.1 Message rejected.',
                '550 5.7.1 Access denied',
                '550-Your message was rejected by this system and was not delivered',
                '550 5.7.1 This message is blocked due to security reason',
                '5.7.1 Message rejected by UNICOMP mail system',
                '550 Administrative prohibition - [^\s]+ banned',
                '530 5.7.57 SMTP; Client was not authenticated to send anonymous mail',
                'Your e-mail was rejected for policy reasons on this gateway',
                '550 Protocol violation',
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
                'This message has been blocked because it contains FortiSpamshield blocking URL',
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
                'Message detected as spam',
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
                '554 5.7.1 [^\s]+: Sender address rejected: LIST_ACCESS_FROM',
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
                '554 5.3.2 Sorry, we do not accept connections from your IP',
                '553 5.7.1 [^\s]+: Client host rejected: SPAM_CLIENT',
                'refused to talk to me: 550 Access denied...',
                '554 [^\s]+ bizsmtp [a-z\d]+ Connection refused from',
                '551 Server access forbidden by your IP',
                '554 5.7.1 Delivery not authorized',
                '554 Denied \[[^\s]+\] \(Mode: normal\)',
                '543 reject by yun-medusa\d+-mta\(ID:[\d\.]{9,}\)',
                '550-Requested action not taken: mailbox unavailable 550-Reject due to policy restrictions',
                '553 5.7.1 <[^\s]+>: Client host rejected: AUTO_CLIENT You have been identified as a spammer. Go Away',
                'Number of \'Received:\' DATA headers exceeds maximum permitted',
                '5.7.0 \([^\s]+\) Message could not be delivered. Please ensure the message is RFC 5322 compliant',
                '554 Message not allowed - Headers are not RFC compliant\[291\]',
                '5.7.1 RFC 2822 specifications for more information',
                '550 RP:ORQ [^\s]+mail.163.com/help/help_spam',
                '521 5.2.1 : AOL will not accept delivery of this message',
                '554 5.7.1 Spam message rejected',
                '550-REJECTED - spamtext',
                '554 Email rejected due to security policies',
                '553 5.7.1 Sensitive words detected',
                '554 delivery error: dd Requested mail action aborted',
                '550 5.7.1 [^\s]+ Message rejected due to local policy',
                '550-domain [^\s]+ suffer screening issues contact',
            ],

            'mailloop' => [
                '554 5.4.14 Hop count exceeded - possible mail loop',
                'routing loop detected',
                ': mail for [^\s]+ loops back to myself',
                'gave this error: Hop count exceeded - possible mail loop',
                '554 5.4.6 Hop count exceeded - possible mail loop',
                'SMTP; Hop count exceeded - possible mail loop',
            ],

            'remoteconfigerror' => [
                '550 Sender IP reverse lookup rejected',
                '474 [^\s]+ no DNS A-data returned',
                'SMTP server not available if you do not have a reverse dns mapping',
                '550 5.1.1 [^\s]+ Your IP has no Reverse DNS',
                '551 Server access [^\s]+ forbidden by invalid RDNS record of your mail server',
                '554 5.7.1 Client host rejected: cannot find your reverse hostname',
                '550 inconsistent or no DNS PTR record for',
                '550 5.7.1 Fix reverse DNS for',
                'refused to talk to me: 554 5.1.8 DNS-P3',
                'refused to talk to me: 554 Client address rejected: No reverse DNS for',
                '501 - Connection Refused: IP Address <[^\s]+> - HELO/EHLO Invalid or Non-Existent Reverse DNS',
                'refused to talk to me: 421 [^\s]+ Your host [^\s]+ has no valid Reverse DNS',
                '554-No SMTP service 554 invalid DNS PTR resource record',
                '554 This server requires PTR for unauthenticated connections',
                'Name service error for name=[^\s]+ type=MX: Malformed or unexpected name server reply',
                '550-5.7.1 [^\s]+ Sorry, your helo has been denied',
                '550 5.7.1 <[^\s]+>: Helo command rejected: Host not found',
                '554 5.7.1 - Connection refused. IP name lookup failed for',
                '554 5.7.1 Helo invalid',
                '554 5.7.1 \[C14\] Missing reverse DNS for',
                '550 No RDNS entry for',
                'said: 553 RP:RDN',
                '554 [^\s]+ Comcast requires that all mail servers must have a PTR record with a valid Reverse DNS entry',
                '501 5.7.1 [^\s]+ Sender IP must resolve',
                '421 4.\d.1 : \(DNS:NR\)',
                '421 4.1.2 [^\s]+: Recipient address rejected: No reverse name for your IP address',
                '451 Blocked - Reverse DNS queries for your IP fail. You cannot send me mail',
                '452 4.1.0 Policy violation. Your host [^\s]+ has no valid Reverse DNS',
                '450 4.7.1 Client host rejected: cannot find your hostname',
                '450 4.7.1 Client host rejected: cannot find your reverse hostname',
                '450 4.7.1 <[^\s]+>: Helo command rejected: Host not found',
                '521 [^\s]+ Service not available - no PTR record for',
                '550-Bad HELO: [^\s]+ does not exist 550 Please see RFC 2821 section',
                '501 <[^\s]+> is invalid or DNS says does not exist',
                '550 5.1.0 <[^\s]+> sender rejected: domain does not have neither a valid MX or A record',
                '451 Missing reverse PTR - please fix it and try again',
                '550 Invalid Domain \[[^\s]+; (LIB|VIR)_420\]',
                '421 [^\s]+ [^\s]+ No reverse DNS \[[^\s]+; (LIB|VIR)_120\]',
                '550 PTR and SPF-softail',
                '550 Reverse DNS lookup failed for host',
                '554-Bad DNS PTR resource record',
                '550 SPF check failed \(Fail\)',
                '554 [^\s]+ cmsmtp Client host rejected: cannot find your hostname',
                '550 5.7.0 HELO argument \[[^\s]+\] is missing a DNS entry',
                '451 4.7.0 [^\s]+ host can\'t be resolved',
                '550 5.7.0 Server [^\s]+ has an invalid PTR record',
                '550 Access denied - Invalid HELO name',
                '450-4.7.1 Client host rejected: cannot find your reverse hostname',
                '550-5.5.1 Server [^\s]+ has an invalid PTR record',
                '550 5.7.0 Your server IP address [^\s]+ does not have a valid reverse DNS entry',
                '450 4.7.1 <[^\s]+>: Sender address rejected: Access denied',
            ],

            'overquota' => [

                'MapiExceptionShutoffQuotaExceeded',
                '\d52 \d.2.2 Over quota',
                '\d52 \d.0.0 User mailbox is overquota',
                '\d5\d [^\s]+ account is full \(quota exceeded\)',
                '552 5.2.2 .*?Quota exceeded',
                '552-Requested mail action aborted: exceeded storage allocation',
                'permission denied. Command output: maildrop: maildir over quota',
                'Message rejected: this mailbox is over quota',
                'Message will exceed maximum mailbox size. Mail rejected',
                '550 Quota is over for this user',
                '550 Mailbox [^\s]+ is over quota, try again later',
                '550 5.2.2 .*?Over quota',
                '550 5.1.1 .*?recipient overquota',
                '451 quota exceeded',
                '451 Mailbox quota exceeded',
                '550 Mailbox over quota',
                'maildir delivery failed: error writing message: Disk quota exceeded',
                'Your message to [^\s]+ was automatically rejected: Not enough disk space',
                '522 sorry, recipient mailbox is full',
                '550 Delivery error.Mailbox of [^\s]+ is FULL',
                '550 RCPT TO:[^\s]+ Mailbox disk quota exceeded',
                'This is a permanent error. The following address\(es\) failed: [^\s]+ Quota exceeded',
                '451 Account [^\s]+ out of quota. Try later',
                '550-Callout verification failed: 550 550 Recipient\'s mailbox is full, user account inactive',
                '450 Disk quota exceed for',
                'Your message cannot be delivered to the following recipients: Recipient address: [^\s]+ Reason: Over quota',
                'Quota exceeded \(mailbox for user is full\)',
                'Sorry, the user\'s maildir has overdrawn his diskspace quota',
                'Sorry, the user [^\s]+ over quota, please try again later',
                '552 Permanent failure, user is over quote',
                '452-4.2.2 The email account that you tried to reach is over quota',
                '552 5.2.2 Mailbox size limit exceeded',
                'error writing message: File too large',
                'temporary failure. Command output: maildrop: maildir over quota',
                ': <<< maildrop: maildir over quota',
                'generated by [^\s]+ mailbox is full',
                '450 4.2.2 [^\s]+: user is overquota',
                '452 4.3.1 [^\s]+Insufficient system storage',
                'This is a permanent error. The following address\(es\) failed:[^\s]+ Mailbox (is )?full',
                'Failed to deliver to [^\s]+ mailbox is full',
                'Failed to deliver to [^\s]+ LOCAL module\(account [^\s]+\) reports: account is full \(quota exceeded\)',
                '552-5.2.2 The email account that you tried to reach is over quota',
                '550 RCPT TO:<[^\s]+> max message size exceeded',
                '550 Account exceeds storage quota',
                '552 Mailbox limit exeeded for this email address',

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
            preg_match('!^x-autoreply: (?<email>(<pfx>.+?)@(?<domain>.+))\s*$!mi', $emailHeaders, $xAutoReply)
            && preg_match('!^reply-to: (?<email>.+)\s*$!mi', $emailHeaders, $replyTo)
            && ($replyTo['email'] == "{$xAutoReply['pfx']}.autoreply@{$xAutoReply['domain']}")
        ) {
            return $this->logAndReturn([$xAutoReply['email']], self::TYPE_IGNORE, 'autoreply', $xAutoReply[0]);
        }

        if (
            preg_match('!^X-Autogenerated: Reply\s*$!mi', $emailHeaders, $ar)
            || preg_match('!^Auto-submitted: auto-generated\s*$!mi', $emailHeaders, $ar)
            || preg_match('!^Auto-Submitted: auto-replied \(vacation\)\s*$!mi', $emailHeaders, $ar)
            || (preg_match('!^X-AutoReply: yes\s*$!mi', $emailHeaders, $ar)
                && (preg_match('!^Auto-Submitted: auto-replied\s*$!mi', $emailHeaders, $asr)
                    || preg_match('!^X-AutoReply-From: (?<email>.+)\s*!mi', $emailHeaders, $xAutoReplyFrom)))
        ) {
            $from = isset($xAutoReplyFrom) ? $xAutoReplyFrom['email'] : $fromEmail;
            $ar = trim($ar[0]);
            $ar = trim(isset($asr) ? "{$ar} & {$asr[0]}" : $ar);
            return $this->logAndReturn([$from], self::TYPE_IGNORE, 'autoreply', $ar);
        }

        if (preg_match('!^Return-Path: <auto-answer@i.ua>!mi', $emailHeaders, $m)) {
            return $this->logAndReturn([$fromEmail], self::TYPE_IGNORE, 'autoreply', $m[0]);
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
        $source = null;
        if(strpos($categoryName, ':')) {
            list($categoryName, $source) = explode(':', $categoryName, 2);
        }

        $result = [
            'emails'     => json_encode($emails),
            'bounceType' => self::BOUNCE_TYPE_MNEMONICS[$bounceType],
            'category'   => $categoryName,
        ];

        if ($pattern) {
            $result['pattern'] = $pattern;
        }

        if ($source) {
            $result['source'] = $source;
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
                        $pattern = preg_replace('!(\.[^+*?\]({\\\])!', '\\\$1', $pattern);
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
        if (preg_match('![\r\n]\s*Subject: (?<subject>.+?)(?=(\r?\n[^\r\n]+:|\r?\n\r?\n))!is', $headers, $m)) {
            foreach (imap_mime_header_decode($m['subject']) as $s) {
                $subject .= $s->charset != 'default' ? iconv($s->charset, 'utf-8', $s->text) : $s->text;
            }
        }
        return preg_replace('!\s+!', ' ', $subject);
    }

    public function getEmailFromHeaders(string $type, string $headers): ?string
    {
        if (preg_match("![\r\n]\s*{$type}:\s*.*?<?(?<email>([a-z\d_]|[a-z\d_][a-z\d._\-]*[a-z\d_\-])@([a-z\d][a-z\d\-]*\.)+[a-z]{2,})>?!is", $headers, $m)) {
            return $m['email'];
        }

        return false;
    }
}
