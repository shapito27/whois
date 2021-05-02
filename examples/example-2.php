<?php

use Shapito27\Whois\WhoisParser;

require_once __DIR__ . '/../vendor/autoload.php';

//whois car.co.il
$whoisText = <<<WHOIS

% The data in the WHOIS database of the .il registry is provided
% by ISOC-IL for information purposes, and to assist persons in 
% obtaining information about or related to a domain name 
% registration record. ISOC-IL does not guarantee its accuracy.
% By submitting a WHOIS query, you agree that you will use this
% Data only for lawful purposes and that, under no circumstances
% will you use this Data to: (1) allow, enable, or otherwise 
% support the transmission of mass unsolicited, commercial 
% advertising or solicitations via e-mail (spam); 
% or  (2) enable high volume, automated, electronic processes that 
% apply to ISOC-IL (or its systems).
% ISOC-IL reserves the right to modify these terms at any time.
% By submitting this query, you agree to abide by this policy.
 
query:        car.co.il

reg-name:     car
domain:       car.co.il

descr:        CADURI NAIM SONS LTD.
descr:        16. Haharash st.
descr:        Tel Aviv
descr:        67613
descr:        Israel
phone:        +972 3 6385757
fax-no:       +972 3 6385757
admin-c:      II-OH2281-IL
tech-c:       II-OH2281-IL
zone-c:       II-OH2281-IL
nserver:      pdns.qos.net.il 
nserver:      sdns.qos.net.il 
validity:     N/A
DNSSEC:       unsigned
status:       Transfer Locked
changed:      registrar AT ns.il 19971104 (Assigned)
changed:      registrar AT ns.il 19980701 (Changed)
changed:      registrar AT ns.il 19990429 (Changed)
changed:      registrar AT ns.il 19990720 (Changed)
changed:      domain-registrar AT isoc.org.il 20000810 (Changed)
changed:      domain-registrar AT isoc.org.il 20020902 (Changed)
changed:      domain-registrar AT isoc.org.il 20050830 (Changed)
changed:      domain-registrar AT isoc.org.il 20150419 (Changed)
changed:      domain-registrar AT isoc.org.il 20150830 (Changed)
changed:      domain-registrar AT isoc.org.il 20150830 (Changed)

person:       Ofir Hason
address      QOS Added Values
address      Hanechoshet
address      TLV
address      69710
address      Israel
phone:        972-3-7668864
fax-no:       972-3-7668868
e-mail:       dns AT qos.net.il
nic-hdl:      II-OH2281-IL
changed:      domain-registrar AT isoc.org.il 20050821

registrar name: Israel Internet Association ISOC-IL
registrar info: www.isoc.org.il

% Rights to the data above are restricted by copyright.

WHOIS;

$parser = new WhoisParser('car.co.il', $whoisText);
$whoisParserResult = $parser->run();

var_dump($whoisParserResult->getWhois());
var_dump($whoisParserResult->getErrorMessage());