<?php

namespace Shapito27\Tests;

use PHPUnit\Framework\TestCase;
use Shapito27\Whois\ParserResult;
use Shapito27\Whois\WhoisParser;

class KZNotAvailableTest extends TestCase
{
    protected $domainName;
    protected $whoisText;
    protected $parserResult;

    protected function setUp(): void
    {
        parent::setUp();

        $this->domainName = 'kaz-football.kz';
        //whois facebook.com
        $this->whoisText = <<<WHOIS
Whois Server for the KZ top level domain name.
This server is maintained by KazNIC Organization, a ccTLD manager for Kazakhstan Republic.

Domain Name............: kaz-football.kz

Organization Using Domain Name
Name...................: Lyakhov Alexandr Egorovich
Organization Name......: Lyakhov Alexandr Egorovich
Street Address.........: 536 Seifullin Ave., 13
City...................: Almaty
State..................: 
Postal Code............: 050022
Country................: KZ

Administrative Contact/Agent
NIC Handle.............: EA108-SL
Name...................: Alexander E. Lyakhov
Phone Number...........: 3272-920-186 
Fax Number.............: 3272-920-186 
Email Address..........: alexel@host.kz

Nameserver in listed order

Primary server.........: ns1.ps.kz
Primary ip address.....: 195.210.46.194, 2a00:5da0:0:1::194

Secondary server.......: ns2.ps.kz
Secondary ip address...: 195.210.46.2, 2a00:5da0:1000::2

Secondary server.......: ns3.ps.kz
Secondary ip address...: 2a00:ab00:1108:177::4, 92.53.88.26


Domain created: 2010-05-21 06:34:24 (GMT+0:00)
Last modified : 2018-03-09 17:51:21 (GMT+0:00)
Domain status : clientTransferProhibited - 
                clientRenewProhibited - 
                
Registar created: KAZNIC
Current Registar: ICPS

WHOIS;
        $parser = new WhoisParser($this->domainName, $this->whoisText);
        $this->parserResult = $parser->run();
        var_dump($this->parserResult->getWhois());
    }

    public function testSuccessfulParsingHasResultParsing(): void
    {
        self::assertInstanceOf(ParserResult::class, $this->parserResult);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldExpirationDate(): void
    {
        self::assertNull($this->parserResult->getWhois()->expirationDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldCreationDate(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->creationDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldUpdateDate(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->updateDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldRegistryDomainId(): void
    {
        self::assertNull($this->parserResult->getWhois()->registryDomainId);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldNameServers(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->nameServers);
    }

    public function testSuccessfulParsingHasNotNullWhoisFieldRegistrar(): void
    {
        self::assertNotNull($this->parserResult->getWhois()->registrar);
    }

    public function testSuccessfulParsingWhoisFieldRegistrarHasNotNullId(): void
    {
        self::assertNull($this->parserResult->getWhois()->registrar->id);
    }

    public function testSuccessfulParsingWhoisFieldRegistrarHasNotNullAbuseContactPhone(): void
    {
        self::assertNull($this->parserResult->getWhois()->registrar->abuseContactPhone);
    }

    public function testSuccessfulParsingWhoisFieldRegistrarHasNotNullAbuseContactEmail(): void
    {
        self::assertNull($this->parserResult->getWhois()->registrar->abuseContactEmail);
    }

    public function testSuccessfulParsingWhoisFieldRegistrarHasNotEmptyName(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->registrar->name);
    }

    public function testSuccessfulParsingIsDomainAvailableFalse(): void
    {
        self::assertFalse($this->parserResult->isDomainAvailable());
    }
}
