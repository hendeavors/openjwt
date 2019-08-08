<?php

namespace Endeavors\OpenJWT\Contracts;

interface Algorithm
{
    const SUPPORTED = [
        'HS256' => ['hash_hmac' =>'SHA256'],
        'HS512' => ['hash_hmac' => 'SHA512'],
        'HS384' => ['hash_hmac' => 'SHA384'],
        'RS256' => ['openssl' => 'SHA256'],
        'RS384' => ['openssl' => 'SHA384'],
        'RS512' => ['openssl' => 'SHA512'],
    ];
}
