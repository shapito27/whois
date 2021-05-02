<?php

use Shapito27\Whois\WhoisParser;

require_once __DIR__ . '/../vendor/autoload.php';

//whois guardian.co.uk
$whoisText = <<<WHOIS2

    Domain name:
        guardian.co.uk

    Data validation:
        Nominet was able to match the registrant's name and address against a 3rd party data source on 30-Oct-2015

    Registrar:
        GoDaddy.com, LLC. [Tag = GODADDY]
        URL: http://uk.godaddy.com

    Relevant dates:
        Registered on: before Aug-1996
        Expiry date:  16-Jun-2023
        Last updated:  13-Apr-2021

    Registration status:
        Registered until expiry date.

    Name servers:
        dns1.p02.nsone.net
        dns2.p02.nsone.net
        dns3.p02.nsone.net
        dns4.p02.nsone.net
        ns01.theguardiandns.com
        ns02.theguardiandns.com
        ns03.theguardiandns.com
        ns04.theguardiandns.com

    WHOIS lookup made at 16:26:30 27-Apr-2021

-- 
This WHOIS information is provided for free by Nominet UK the central registry
for .uk domain names. This information and the .uk WHOIS are:

    Copyright Nominet UK 1996 - 2021.

You may not access the .uk WHOIS or use any data from it except as permitted
by the terms of use available in full at https://www.nominet.uk/whoisterms,
which includes restrictions on: (A) use of the data for advertising, or its
repackaging, recompilation, redistribution or reuse (B) obscuring, removing
                                                                   or hiding any or all of this notice and (C) exceeding query rate or volume
limits. The data is provided on an 'as-is' basis and may lag behind the
register. Access may be withdrawn or restricted at any time.

WHOIS2;


$parser = new WhoisParser('guardian.co.uk', $whoisText);
$whoisParserResult = $parser->run();

var_dump($whoisParserResult->getWhois());
var_dump($whoisParserResult->getErrorMessage());