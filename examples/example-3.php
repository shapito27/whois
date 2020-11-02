<?php

use Shapito27\Whois\WhoisParser;

require_once __DIR__ . '/../vendor/autoload.php';

//whois guardian.co.uk
$whoisText = "\n
    Domain name:\n
        guardian.co.uk\n
\n
    Data validation:\n
        Nominet was able to match the registrant's name and address against a 3rd party data source on 30-Oct-2015\n
\n
    Registrar:\n
        GoDaddy.com, LLC. [Tag = GODADDY]\n
        URL: http://uk.godaddy.com\n
\n
    Relevant dates:\n
        Registered on: before Aug-1996\n
        Expiry date:  16-Jun-2022\n
        Last updated:  31-Oct-2019\n
\n
    Registration status:\n
        Registered until expiry date.\n
\n
    Name servers:\n
        dns1.p02.nsone.net\n
        dns2.p02.nsone.net\n
        dns3.p02.nsone.net\n
        dns4.p02.nsone.net\n
        ns01.theguardiandns.com\n
        ns02.theguardiandns.com\n
        ns03.theguardiandns.com\n
        ns04.theguardiandns.com\n
\n
    WHOIS lookup made at 13:52:47 02-Nov-2020\n
\n
-- \n
This WHOIS information is provided for free by Nominet UK the central registry\n
for .uk domain names. This information and the .uk WHOIS are:\n
\n
    Copyright Nominet UK 1996 - 2020.\n
\n
You may not access the .uk WHOIS or use any data from it except as permitted\n
by the terms of use available in full at https://www.nominet.uk/whoisterms,\n
which includes restrictions on: (A) use of the data for advertising, or its\n
repackaging, recompilation, redistribution or reuse (B) obscuring, removing\n
or hiding any or all of this notice and (C) exceeding query rate or volume\n
limits. The data is provided on an 'as-is' basis and may lag behind the\n
register. Access may be withdrawn or restricted at any time. \n
";

$parser = new WhoisParser($whoisText);
$whoisObject = $parser->run();

var_dump($whoisObject);