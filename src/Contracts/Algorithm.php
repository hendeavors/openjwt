<?php

namespace Endeavors\OpenJWT\Contracts;

interface Algorithm
{
    const SUPPORTED = [
        'HS256' => ['hash_hmac' =>'SHA256'],
        'HS512' => ['hash_hmac' => 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    ];
}
