<?php

namespace Shapito27\Whois\Formatters;

use Carbon\Carbon;
use Carbon\Exceptions\InvalidFormatException;
use Exception;
use Shapito27\Whois\Whois;

abstract class AbstractFormatter
{
    /** @var string */
    public const DEFAULT_DATE_FORMAT = 'Y-m-d H:i:s';

    /** @var string */
    protected $dateFormat = self::DEFAULT_DATE_FORMAT;

    /** @var array */
    protected $creationDateSynonyms = [];
    /** @var array */
    protected $updateDateSynonyms = [];
    /** @var array */
    protected $expiryDateSynonyms = [];
    /** @var array */
    protected $nameServerSynonyms = [];
    /** @var array */
    protected $registrarSynonyms = [];

    /** @var array */
    protected $registrarIanaId = [
        'Registrar IANA ID:',
    ];

    /** @var array */
    protected $registryDomainIdSynonyms = [
        'register number....:',
        'Registry Domain ID:',
    ];

    /** @var array */
    protected $registrarAbuseContactEmailSynonyms = [
        'Registrar Abuse Contact Email:',
    ];

    /** @var array */
    protected $registrarAbuseContactPhoneSynonyms = [
        'Registrar Abuse Contact Phone:',
    ];

    /** @var array */
    protected $domainAvailableSynonyms = [];

    /** @var array */
    protected $unnecessaryWords = ['before', 'CLST'];

    /** @var string */
    protected const DB_PATH = __DIR__.'/../../db/';

    /**
     *
     */
    public function __construct()
    {
        $this->setCreationDateSynonyms(
            json_decode(file_get_contents(self::DB_PATH.'creation_date_synonyms.json'), true)['values']
        );
        $this->setUpdateDateSynonyms(
            json_decode(file_get_contents(self::DB_PATH.'update_date_synonyms.json'), true)['values']
        );
        $this->setExpiryDateSynonyms(
            json_decode(file_get_contents(self::DB_PATH.'expiry_date_synonyms.json'), true)['values']
        );
        $this->setNameServerSynonyms(
            json_decode(file_get_contents(self::DB_PATH.'name_server_synonyms.json'), true)['values']
        );
        $this->setDomainAvailableSynonyms(
            json_decode(file_get_contents(self::DB_PATH.'domain_available_synonyms.json'), true)['values']
        );
        $this->setRegistrarSynonyms(
            json_decode(file_get_contents(self::DB_PATH.'registrar_synonyms.json'), true)['values']
        );
    }

    /**
     * @param  string  $whoisPlainText
     *
     * @return Whois
     */
    abstract public function convertToWhoisObject(string $whoisPlainText);

    /**
     * @param  string  $date
     *
     * @return string
     */
    protected function parseDate(string $date): string
    {
        try {
            return Carbon::parse($date)->format($this->dateFormat);
        } catch (InvalidFormatException $invalidFormatException) {
            //try to change format
            try {
                $date = str_replace('.', '-', $date);

                return Carbon::parse($date)->format($this->dateFormat);
            } catch (Exception $exception) {
                return $date;
            }
        } catch (Exception $exception) {
            return $date;
        }
    }

    /**
     * @param  string  $dateFormat
     */
    public function setDateFormat(string $dateFormat): void
    {
        $this->dateFormat = $dateFormat;
    }

    /**
     * @param  string[]  $creationDateSynonyms
     */
    public function setCreationDateSynonyms(array $creationDateSynonyms): void
    {
        $this->creationDateSynonyms = $creationDateSynonyms;
    }

    /**
     * @param  string[]  $updateDateSynonyms
     */
    public function setUpdateDateSynonyms(array $updateDateSynonyms): void
    {
        $this->updateDateSynonyms = $updateDateSynonyms;
    }

    /**
     * @param  string[]  $expiryDateSynonyms
     */
    public function setExpiryDateSynonyms(array $expiryDateSynonyms): void
    {
        $this->expiryDateSynonyms = $expiryDateSynonyms;
    }

    /**
     * @param  string[]  $nameServerSynonyms
     */
    public function setNameServerSynonyms(array $nameServerSynonyms): void
    {
        $this->nameServerSynonyms = $nameServerSynonyms;
    }

    /**
     * @param  string[]  $registrarSynonyms
     */
    public function setRegistrarSynonyms(array $registrarSynonyms): void
    {
        $this->registrarSynonyms = $registrarSynonyms;
    }

    /**
     * @param  string[]  $registrarIanaId
     */
    public function setRegistrarIanaId(array $registrarIanaId): void
    {
        $this->registrarIanaId = $registrarIanaId;
    }

    /**
     * @param  string[]  $registryDomainIdSynonyms
     */
    public function setRegistryDomainIdSynonyms(array $registryDomainIdSynonyms): void
    {
        $this->registryDomainIdSynonyms = $registryDomainIdSynonyms;
    }

    /**
     * @param  string[]  $registrarAbuseContactEmailSynonyms
     */
    public function setRegistrarAbuseContactEmailSynonyms(array $registrarAbuseContactEmailSynonyms): void
    {
        $this->registrarAbuseContactEmailSynonyms = $registrarAbuseContactEmailSynonyms;
    }

    /**
     * @param  string[]  $registrarAbuseContactPhoneSynonyms
     */
    public function setRegistrarAbuseContactPhoneSynonyms(array $registrarAbuseContactPhoneSynonyms): void
    {
        $this->registrarAbuseContactPhoneSynonyms = $registrarAbuseContactPhoneSynonyms;
    }

    /**
     * @param  string[]  $domainAvailableSynonyms
     */
    public function setDomainAvailableSynonyms(array $domainAvailableSynonyms): void
    {
        $this->domainAvailableSynonyms = $domainAvailableSynonyms;
    }

    /**
     * @param  array  $unnecessaryWords
     */
    public function setUnnecessaryWords(array $unnecessaryWords): void
    {
        $this->unnecessaryWords = $unnecessaryWords;
    }

    /**
     * @param  string  $creationDateSynonym
     */
    public function addCreationDateSynonym(string $creationDateSynonym): void
    {
        $this->creationDateSynonyms[] = $creationDateSynonym;
    }

    /**
     * @param  string  $updateDateSynonym
     */
    public function addUpdateDateSynonym(string $updateDateSynonym): void
    {
        $this->updateDateSynonyms[] = $updateDateSynonym;
    }

    /**
     * @param  string  $expiryDateSynonym
     */
    public function addExpiryDateSynonym(string $expiryDateSynonym): void
    {
        $this->expiryDateSynonyms[] = $expiryDateSynonym;
    }

    /**
     * @param  string  $nameServerSynonym
     */
    public function addNameServerSynonym(string $nameServerSynonym): void
    {
        $this->nameServerSynonyms[] = $nameServerSynonym;
    }

    /**
     * @param  string  $registrarSynonym
     */
    public function addRegistrarSynonym(string $registrarSynonym): void
    {
        $this->registrarSynonyms[] = $registrarSynonym;
    }

    /**
     * @param  string  $registrarIanaId
     */
    public function addRegistrarIanaId(string $registrarIanaId): void
    {
        $this->registrarIanaId[] = $registrarIanaId;
    }

    /**
     * @param  string  $registryDomainIdSynonym
     */
    public function addRegistryDomainIdSynonym(string $registryDomainIdSynonym): void
    {
        $this->registryDomainIdSynonyms[] = $registryDomainIdSynonym;
    }

    /**
     * @param  string  $registrarAbuseContactEmailSynonym
     */
    public function addRegistrarAbuseContactEmailSynonym(string $registrarAbuseContactEmailSynonym): void
    {
        $this->registrarAbuseContactEmailSynonyms[] = $registrarAbuseContactEmailSynonym;
    }

    /**
     * @param  string  $registrarAbuseContactPhoneSynonym
     */
    public function addRegistrarAbuseContactPhoneSynonym(string $registrarAbuseContactPhoneSynonym): void
    {
        $this->registrarAbuseContactPhoneSynonyms[] = $registrarAbuseContactPhoneSynonym;
    }

    /**
     * @param  string  $domainNotFoundSynonym
     */
    public function addDomainNotFoundSynonym(string $domainNotFoundSynonym): void
    {
        $this->domainAvailableSynonyms[] = $domainNotFoundSynonym;
    }

    public static function name()
    {
        return static::class;
    }
}