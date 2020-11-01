<?php

namespace Shapito27\Whois;

use RuntimeException;
use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

/**
 * Class WhoisParser
 * @package Shapito27\Whois
 */
class WhoisParser
{
    /** @var string */
    private $whoisText;

    private $creationDateSynonyms = [
        'domain_dateregistered:',
        'record created:',
        'Creation Date:',
        'created:',
        'Registered on:',
        'Registered:',
        'Registration Time:',
        '[最終更新]',
        '[接続年月日]',
        '[登録年月日]',
    ];

    private $expiryDateSynonyms = [
        'Registry Expiry Date:',
        'Expiry date:',
        'Expire Date:',
        'Expiration Time:',
        'paid-till:',
        'expires:',
        '[有効期限]',
    ];

    private $updateDateSynonyms = [
        'domain_datelastmodified:',
        'Last updated date:',
        '[Last Update]',
        'Updated Date:',
        'Last updated:',
        'Last Modified:',
        'modified:',
        'changed:',
        '[最終更新]',
    ];

    private $nameServerSynonyms = [
        'Name Server:',
        'nserver:',
        'Name servers:',
        'Hostname:',
        'p. [ネームサーバ]',
        'ns_name_01:',
        'ns_name_02:',
        'ns_name_03:',
        'ns_name_04:',
        '[Name Server]',
    ];

    private $registrarSynonyms = [
        '[Registrant]',
        'registrar_name:',
        'Registrar:',
    ];

    private $registrarIanaId = [
        'Registrar IANA ID:',
    ];

    private $registrarAbuseContactEmailSynonyms = [
        'Registrar Abuse Contact Email:',
    ];

    private $registrarAbuseContactPhoneSynonyms = [
        'Registrar Abuse Contact Phone:',
    ];

    private $registryDomainIdSynonyms = [
        'Registry Domain ID:',
    ];

    private $unnecessaryWord = 'before';

    /** @var int available for registration */
    public const DOMAIN_STATUS_AVAILABLE = 0;
    /** @var int domain already registered */
    public const DOMAIN_STATUS_REGISTERED = 1;
    /** @var int status not found. Reasons: parsing problems, wrong whois server response */
    public const DOMAIN_STATUS_NOT_FOUND = 2;

    /**
     * WhoisParser constructor.
     *
     * @param  string  $whoisText
     */
    public function __construct(string $whoisText)
    {
        $this->whoisText = $whoisText;
    }

    /**
     * @return Whois
     */
    public function run(): Whois
    {
        $whoisObject         = new Whois();
        $whoisObject->status = self::DOMAIN_STATUS_AVAILABLE;

        try {
            $info = $this->whoisText;

            $whoisStrings = explode("\n", $info);

            foreach ($whoisStrings as $lineNumber => $line) {
                if ($whoisObject->creationDate === null) {
                    //looking for creation date
                    foreach ($this->creationDateSynonyms as $creationDateSynonym) {
                        if (stripos($line, $creationDateSynonym) !== false) {
                            if (strpos($line, $this->unnecessaryWord) !== false) {
                                $line = str_replace($this->unnecessaryWord, '', $line);
                            }
                            $creationDate = trim(str_ireplace($creationDateSynonym, '', $line));
                            if (!empty($creationDate)) {
                                $whoisObject->creationDate = $creationDate;
                                break;
                            }
                        }
                    }
                }

                //looking for expiry date
                if ($whoisObject->expirationDate === null) {
                    foreach ($this->expiryDateSynonyms as $expiryDateSynonym) {
                        if (stripos($line, $expiryDateSynonym) !== false) {
                            $expirationDate = trim(str_ireplace($expiryDateSynonym, '', $line));
                            if (!empty($expirationDate)) {
                                $whoisObject->expirationDate = $expirationDate;
                                break;
                            }
                        }
                    }
                }

                //looking for updated date
                if ($whoisObject->updateDate === null) {
                    foreach ($this->updateDateSynonyms as $updateDateSynonym) {
                        if (stripos($line, $updateDateSynonym) !== false) {
                            $updateDate = trim(str_ireplace($updateDateSynonym, '', $line));
                            if (!empty($updateDate)) {
                                $whoisObject->updateDate = $updateDate;
                                break;
                            }
                        }
                    }
                }

                foreach ($this->registryDomainIdSynonyms as $registryDomainIdSynonym) {
                    if (stripos($line, $registryDomainIdSynonym) !== false) {
                        $registryDomainId = trim(str_ireplace($registryDomainIdSynonym, '', $line));
                        if (!empty($registryDomainId)) {
                            $whoisObject->registryDomainId = $registryDomainId;
                            break;
                        }
                    }
                }

                foreach ($this->registrarSynonyms as $registrarSynonym) {
                    if ((stripos($line, $registrarSynonym) !== false)) {
                        $registrarName = trim(str_ireplace($registrarSynonym, '', $line));
                        if (!empty($registrarName)) {
                            if ($whoisObject->registrar === null) {
                                $whoisObject->registrar = new Registrar();
                            }
                            $whoisObject->registrar->name = $registrarName;
                            break;
                        }
                    }
                }

                foreach ($this->registrarIanaId as $registrarIanaId) {
                    if (stripos($line, $registrarIanaId) !== false) {
                        $registrarId = trim(str_ireplace($registrarIanaId, '', $line));
                        if (!empty($registrarId)) {
                            if ($whoisObject->registrar === null) {
                                $whoisObject->registrar = new Registrar();
                            }
                            $whoisObject->registrar->id = $registrarId;
                            break;
                        }
                    }
                }

                foreach ($this->registrarAbuseContactEmailSynonyms as $registrarAbuseContactEmailSynonym) {
                    if (stripos($line, $registrarAbuseContactEmailSynonym) !== false) {
                        $registrarAbuseContactEmail = trim(str_ireplace($registrarAbuseContactEmailSynonym, '', $line));
                        if (!empty($registrarAbuseContactEmail)) {
                            if ($whoisObject->registrar === null) {
                                $whoisObject->registrar = new Registrar();
                            }
                            $whoisObject->registrar->abuseContactEmail = $registrarAbuseContactEmail;
                            break;
                        }
                    }
                }

                foreach ($this->registrarAbuseContactPhoneSynonyms as $registrarAbuseContactPhoneSynonym) {
                    if (stripos($line, $registrarAbuseContactPhoneSynonym) !== false) {
                        $registrarAbuseContactPhone = trim(str_ireplace($registrarAbuseContactPhoneSynonym, '', $line));
                        if (!empty($registrarAbuseContactPhone)) {
                            if ($whoisObject->registrar === null) {
                                $whoisObject->registrar = new Registrar();
                            }
                            $whoisObject->registrar->abuseContactPhone = $registrarAbuseContactPhone;
                            break;
                        }
                    }
                }

                //looking for name_servers
                foreach ($this->nameServerSynonyms as $nameServerSynonym) {
                    if (stripos($line, $nameServerSynonym) !== false) {
                        $nameServer = strtolower(trim(str_ireplace($nameServerSynonym, '', $line)));
                        if (!empty($nameServer)) {
                            //if have other data we do not need after space
                            if (strpos($nameServer, ' ') !== false) {
                                $nameServer = substr($nameServer, 0, strpos($nameServer, ' '));
                            }
                            if (in_array($nameServer, $whoisObject->nameServers) === false) {
                                $whoisObject->nameServers[] = $nameServer;
                            }
                            break;
                        }
                    }
                }
            }

            // If there are data, we will count this as registered.
            if ($whoisObject->isRegistered()) {
                $whoisObject->status = self::DOMAIN_STATUS_REGISTERED;
            }
        } catch (RuntimeException $e) {
            $whoisObject->status = self::DOMAIN_STATUS_NOT_FOUND;
        }

        return $whoisObject;
    }
}
