<?php

namespace Shapito27\Tests;

use PHPUnit\Framework\TestCase;
use Shapito27\Whois\ParserResult;
use Shapito27\Whois\WhoisParser;

class KGNotAvailableTest extends TestCase
{
    protected $domainName;
    protected $whoisText;
    protected $parserResult;

    protected function setUp(): void
    {
        parent::setUp();

        $this->domainName = 'stat.kg';
        //whois facebook.com
        $this->whoisText = <<<WHOIS
% This is the .kg ccTLD Whois server
% Register your own domain at http://www.cctld.kg
% Use @cctld_kg_bot telegram bot for whois service

Domain STAT.KG 

Administrative Contact:
   PID: 7124-KG

Technical Contact:
   PID: 7124-KG

Billing Contact:
   PID: 7124-KG

Domain support: ISP AsiaInfo (+996 312 964488)

Record created: Sat Jan 25 18:26:32 2003
Record last updated on:  Sat Jan 25 18:26:32 2003
Record expires on: Wed Feb 23 23:59:00 2022

Name servers in the listed order:

NS1.ELCAT.KG 212.42.96.1
NS2.ELCAT.KG 212.42.96.2

WHOIS;
        $parser = new WhoisParser($this->domainName, $this->whoisText);
        $this->parserResult = $parser->run();
    }

    public function testSuccessfulParsingHasResultParsing(): void
    {
        self::assertInstanceOf(ParserResult::class, $this->parserResult);
    }

    public function testSuccessfulParsingNoError(): void
    {
        self::assertEmpty($this->parserResult->getErrorMessage());
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldExpirationDate(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->expirationDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldCreationDate(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->creationDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldUpdateDate(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->updateDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldNameServers(): void
    {
        self::assertNotEmpty($this->parserResult->getWhois()->nameServers);
    }

    public function testSuccessfulParsingIsDomainAvailableFalse(): void
    {
        self::assertFalse($this->parserResult->isDomainAvailable());
    }
}
