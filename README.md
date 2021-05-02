# Whois parser
Tool helps parsing whois response. 

For example you have whois response as plain text:
```angular2html

    Domain name:
        auto.uk

    Data validation:
        Nominet was able to match the registrant's name and address against a 3rd party data source on 14-Dec-2017

    Registrar:
        eNom LLC [Tag = ENOM]
        URL: http://www.enom.com

    Relevant dates:
        Registered on: 23-Jun-2016
        Expiry date:  23-Jun-2021
        Last updated:  25-May-2020

    Registration status:
        Registered until expiry date.

    Name servers:
        a.ns.keyweb.org
        b.ns.keyweb.org
        c.ns.keyweb.de

    WHOIS lookup made at 05:43:54 29-Apr-2021

-- 
This WHOIS information is provided for free by Nominet UK the central registry
for .uk domain names. This information and the .uk WHOIS are:

    Copyright Nominet UK 1996 - 2021.


```
This package analyzes it and return object with structured data.


## Install
```composer require shapito27/whois-parser```
## Example
([more detailed example](https://github.com/shapito27/whois/blob/main/tests/WhoisParserTest.php))

lets imagine you use shell command ```whois facebook.com``` and want to parse it.

 **Input**: domain name and ```$whoisText``` is response of shell command
 ```
//set domain name and output of its whois data
$parser = new \Shapito27\Whois\WhoisParser('facebook.com', $whoisText);

//run parsing whois data
$whoisParserResult = $parser->run();

//check if any error
if (!empty($whoisParserResult->getErrorMessage())) {
     die($whoisParserResult->getErrorMessage());
 }

//get and output whois object 
var_dump($whoisParserResult->getWhois());
```

 **Output**:
 ```
Shapito27\Whois\Whois::__set_state(array(
   'status' => 1,
   'creationDate' => '1997-03-29 05:00:00',
   'updateDate' => '2020-03-10 18:53:59',
   'expirationDate' => '2028-03-30 04:00:00',
   'nameServers' => 
  array (
    0 => 'a.ns.facebook.com',
    1 => 'b.ns.facebook.com',
    2 => 'c.ns.facebook.com',
    3 => 'd.ns.facebook.com',
  ),
   'registrar' => 
  Shapito27\Whois\Registrar::__set_state(array(
     'id' => '3237',
     'name' => 'RegistrarSafe, LLC',
     'abuseContactEmail' => 'abusecomplaints@registrarsafe.com',
     'abuseContactPhone' => '+1.6503087004',
  )),
   'registryDomainId' => '2320948_DOMAIN_COM-VRSN',
   'errorMessage' => NULL,
))
```
**Parse inside loop**

To avoid parsing config on each iterration define parser outside the loop. 
 ```
$domains = [
'facebook.com' => 'facebook whois text',
 'google.com' => 'google whois text'
];

//set domain name and output of its whois data
$parser = new \Shapito27\Whois\WhoisParser();

foreach($domains as $domain => $whoisText) {
    $parser->setDomainName($domain);
    //set formatter each iteration
    $parser->detectFormat();
    $parser->setWhoisText($whoisText);
    
    //run parsing whois data
    $whoisParserResult = $parser->run();
    
    //check if any error
    if (!empty($whoisParserResult->getErrorMessage())) {
         die($whoisParserResult->getErrorMessage());
     }
    
    //get and output whois object 
    var_dump($whoisParserResult->getWhois());
    //display errors
    var_dump($whoisParserResult->getErrorMessage());
}
```