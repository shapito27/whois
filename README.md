# Whois parser
Lib for parsing whois response. 
It takes response from any whois server and return object with structured data.


## Install
```composer require shapito27/whois-parser```
## Example
([more detailed example](https://github.com/shapito27/whois/blob/main/tests/WhoisParserTest.php))

 **Input**: response of shell command ```whois facebook.com``` pass as ```$whoisText```
 ```
$parser = new WhoisParser($whoisText);
$whoisObject = $parser->run();
var_dump($whoisObject);
```

 **Output**:
 ```
   ["status"]=>
   int(1)
   ["errorMessage"]=>
   NULL
   ["nameServers"]=>
   array(4) {
     [0]=>
     string(17) "a.ns.facebook.com"
     [1]=>
     string(17) "b.ns.facebook.com"
     [2]=>
     string(17) "c.ns.facebook.com"
     [3]=>
     string(17) "d.ns.facebook.com"
   }
   ["registrar"]=>
   object(Shapito27\Whois\DTO\Registrar)#52 (2) {
     ["id"]=>
     string(4) "3237"
     ["name"]=>
     string(18) "RegistrarSafe, LLC"
   }
   ["creationDate"]=>
   string(20) "1997-03-29T05:00:00Z"
   ["updateDate"]=>
   string(20) "2020-03-10T18:53:59Z"
   ["expirationDate"]=>
   string(20) "2028-03-30T04:00:00Z"
   ["registryDomainId"]=>
   string(23) "2320948_DOMAIN_COM-VRSN"
 }
```
