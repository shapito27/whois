<?php

namespace Shapito27\Whois\Formatters;

class FormatterFactory
{
    //domain zones which use similar format.
    public static $similarZones = [
        'ac.uk' => 'uk',
    ];

    /**
     * @param  string|null  $domainZone
     *
     * @return AbstractFormatter
     */
    public static function create(string $domainZone = null): AbstractFormatter
    {
        if ($domainZone === null) {
            return new BaseFormatter();
        }

        if (isset(self::$similarZones[$domainZone])) {
            $domainZone = self::$similarZones[$domainZone];
        }

        //from co.uk to couk
        if(strpos($domainZone, '.')) {
            $domainZone = str_replace('.', '', $domainZone);
        }

        $newFormatter = '\Shapito27\Whois\Formatters\\' . strtoupper($domainZone);
        if (!class_exists($newFormatter)) {
            return new BaseFormatter();
        }

        return new $newFormatter;
    }
}