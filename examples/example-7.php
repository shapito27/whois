<?php

use Shapito27\Whois\WhoisParser;

require_once __DIR__ . '/../vendor/autoload.php';

//whois saberweb.com.br
$whoisText = <<<WHOIS

% Copyright (c) Nic.br
%  The use of the data below is only permitted as described in
%  full by the terms of use at https://registro.br/termo/en.html ,
%  being prohibited its distribution, commercialization or
%  reproduction, in particular, to use it for advertising or
%  any similar purpose.
%  2021-04-29T07:03:38-03:00 - IP: 202.187.124.244

domain:      saberweb.com.br
owner:       Jonatha Nascimento
owner-c:     JONAS162
tech-c:      JONAS162
nserver:     connie.ns.cloudflare.com
nsstat:      20210424 AA
nslastaa:    20210424
nserver:     norman.ns.cloudflare.com
nsstat:      20210424 AA
nslastaa:    20210424
saci:        yes
created:     20200415 #20895753
changed:     20210408
expires:     20220415
status:      published

nic-hdl-br:  JONAS162
person:      Jonatha Nascimento
created:     20150821
changed:     20191030

% Security and mail abuse issues should also be addressed to
% cert.br, http://www.cert.br/ , respectivelly to cert@cert.br
% and mail-abuse@cert.br
%
% whois.registro.br accepts only direct match queries. Types
% of queries are: domain (.br), registrant (tax ID), ticket,
% provider, CIDR block, IP and ASN.

WHOIS;

$parser = new WhoisParser('saberweb.com.br', $whoisText);
$whoisParserResult = $parser->run();

var_dump($whoisParserResult->getWhois());