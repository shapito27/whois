<?php

namespace Shapito27\Tests;

use PHPUnit\Framework\TestCase;
use Shapito27\Whois\ParserResult;
use Shapito27\Whois\WhoisParser;

class KZAvailableTest extends TestCase
{
    protected $domainName;
    protected $whoisText;
    protected $parserResult;

    protected function setUp(): void
    {
        parent::setUp();

        $this->domainName = 'k0asdf90kalksdf89.kz';
        //whois facebook.com
        $this->whoisText = <<<WHOIS
Whois Server for the KZ top level domain name.
This server is maintained by KazNIC Organization, a ccTLD manager for Kazakhstan Republic.

*** Nothing found for this query.

WHOIS;
        $parser = new WhoisParser($this->domainName, $this->whoisText);
        $this->parserResult = $parser->run();
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
        self::assertNull($this->parserResult->getWhois()->creationDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldUpdateDate(): void
    {
        self::assertNull($this->parserResult->getWhois()->updateDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldNameServers(): void
    {
        self::assertEmpty($this->parserResult->getWhois()->nameServers);
    }

    public function testSuccessfulParsingHasNotNullWhoisFieldRegistrar(): void
    {
        self::assertNull($this->parserResult->getWhois()->registrar);
    }

    public function testSuccessfulParsingIsDomainAvailableTrue(): void
    {
        self::assertTrue($this->parserResult->isDomainAvailable());
    }
}
