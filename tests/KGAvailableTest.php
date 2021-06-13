<?php

namespace Shapito27\Tests;

use PHPUnit\Framework\TestCase;
use Shapito27\Whois\ParserResult;
use Shapito27\Whois\WhoisParser;

class KGAvailableTest extends TestCase
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

Domain JJ323HJ2H34.KG

Data not found. This domain is available for registration.

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
        self::assertEmpty($this->parserResult->getWhois()->expirationDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldCreationDate(): void
    {
        self::assertEmpty($this->parserResult->getWhois()->creationDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldUpdateDate(): void
    {
        self::assertEmpty($this->parserResult->getWhois()->updateDate);
    }

    public function testSuccessfulParsingHasNotEmptyWhoisFieldNameServers(): void
    {
        self::assertEmpty($this->parserResult->getWhois()->nameServers);
    }

    public function testSuccessfulParsingIsDomainAvailableTrue(): void
    {
        self::assertTrue($this->parserResult->isDomainAvailable());
    }
}
