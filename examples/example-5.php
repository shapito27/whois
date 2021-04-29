<?php

use Shapito27\Whois\WhoisParser;

require_once __DIR__ . '/../vendor/autoload.php';

//whois UN.ORG
$whoisText = <<<WHOIS

Domain:
	gold.ac.uk

Registered For:
	Goldsmiths College

Domain Owner:
	Goldsmiths' College

Registered By:
	Jisc Services Limited

Servers:
	ddimaster.gold.ac.uk	158.223.2.249
	ddimember.gold.ac.uk	158.223.2.250
	ns2.ja.net	
	ns3.ja.net	

Registrant Contact:
	Daniel Rubie

Registrant Address:
	IT Services, Infrastructure Team
	Lewisham Way
	New Cross
	London
	SE14 6NW
	United Kingdom
	+44 207 078 5469 (Phone)
	infrastructure@gold.ac.uk

Renewal date:
	Tuesday 17th Aug 2021

Entry updated:
	Friday 17th May 2019

Entry created:
	Friday 14th November 2003


WHOIS;

$parser = new WhoisParser('gold.ac.uk', $whoisText);
$whoisParserResult = $parser->run();

var_dump($whoisParserResult->getWhois());