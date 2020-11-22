<?php

use Shapito27\Whois\WhoisParser;

require_once __DIR__ . '/../vendor/autoload.php';

//whois UN.ORG
$whoisText = <<<WHOIS
Domain Name: UN.ORG\n
Registry Domain ID: D404063-LROR\n
Registrar WHOIS Server: whois.networksolutions.com\n
Registrar URL: http://www.networksolutions.com\n
Updated Date: 2018-01-15T01:14:37Z\n
Creation Date: 1995-01-31T05:00:00Z\n
Registry Expiry Date: 2024-02-01T05:00:00Z\n
Registrar Registration Expiration Date:\n
Registrar: Network Solutions, LLC\n
Registrar IANA ID: 2\n
Registrar Abuse Contact Email: abuse@web.com\n
Registrar Abuse Contact Phone: +1.8003337680\n
Reseller:\n
Domain Status: ok https://icann.org/epp#ok\n
Registrant Organization: United Nations\n
Registrant State/Province: NY\n
Registrant Country: US\n
Name Server: NS1.UN.ORG\n
Name Server: NS2.UN.ORG\n
Name Server: NS3.UN.ORG\n
DNSSEC: unsigned\n
URL of the ICANN Whois Inaccuracy Complaint Form https://www.icann.org/wicf/)\n
>>> Last update of WHOIS database: 2020-11-02T13:51:53Z <<<\n
\n
For more information on Whois status codes, please visit https://icann.org/epp\n
\n
Access to Public Interest Registry WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the Public Interest Registry registry database. The data in this record is provided by Public Interest Registry for informational purposes only, and Public Interest Registry does not guarantee its accuracy. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Afilias except as reasonably necessary to register domain names or modify existing registrations. All rights reserved. Public Interest Registry reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy.\n
\n
The Registrar of Record identified in this output may have an RDDS service that can be queried for additional information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.\n
WHOIS;

$parser = new WhoisParser('un.org', $whoisText);
$whoisParserResult = $parser->run();

var_dump($whoisParserResult->getWhois());