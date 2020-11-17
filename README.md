# Whois parser
Lib for parsing whois response. 
It takes response from any whois server and return object with structured data.


## Install
```composer require shapito27/whois-parser```
## Example
([more detailed example](https://github.com/shapito27/whois/blob/main/tests/WhoisParserTest.php))

 **Input**: response of shell command ```whois facebook.com``` pass as ```$whoisText```
 ```
//set domain name and output of its whois data
$parser = new \Shapito27\Whois\WhoisParser('facebook.com', $whoisText);

//you can set dates format in result
$parser->setDateFormat('Y-m-d H:i:s');

//run parsing whois data
$parserResult = $parser->run();

//check if any error
if (!empty($whoisParserResult->getErrorMessage())) {
     die($whoisParserResult->getErrorMessage());
 }

//get and output whois object 
var_dump($parserResult->getWhois());
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
