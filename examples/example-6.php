<?php

use Shapito27\Whois\WhoisParser;

require_once __DIR__ . '/../vendor/autoload.php';

//whois ucsd.edu
$whoisText = <<<WHOIS
This Registry database contains ONLY .EDU domains.
The data in the EDUCAUSE Whois database is provided
by EDUCAUSE for information purposes in order to
assist in the process of obtaining information about
or related to .edu domain registration records.

The EDUCAUSE Whois database is authoritative for the
.EDU domain.

A Web interface for the .EDU EDUCAUSE Whois Server is
available at: http://whois.educause.edu

By submitting a Whois query, you agree that this information
will not be used to allow, enable, or otherwise support
the transmission of unsolicited commercial advertising or
solicitations via e-mail.  The use of electronic processes to
harvest information from this server is generally prohibited
except as reasonably necessary to register or modify .edu
domain names.

-------------------------------------------------------------

Domain Name: UCSD.EDU

Registrant:
	University of California at San Diego
	Information Technology Services
	9500 Gilman Dr. Mail code 0903
	La Jolla, CA 92093-0903
	US

Administrative Contact:
	Nicole Lewis
	University of California at San Diego
	ITS-Information Technology Services
	9500 Gilman Dr Mail code 0903
	La Jolla, CA 92093-0903
	US
	+1.8588222926
	hostmaster@ucsd.edu

Technical Contact:
	Nicole Lewis
	University of California at San Diego
	ITS-Information Technology Services
	9500 Gilman Dr Mail code 0903
	La Jolla, CA 92093-0903
	US
	+1.8588222926
	hostmaster@ucsd.edu

Name Servers:
	NS-AUTH2.UCSD.EDU
	NS-AUTH3.UCSD.EDU

Domain record activated:    09-Dec-1985
Domain record last updated: 25-Mar-2021
Domain expires:             31-Jul-2021
WHOIS;

$parser = new WhoisParser('ucsd.edu', $whoisText);
$whoisParserResult = $parser->run();

var_dump($whoisParserResult->getWhois());