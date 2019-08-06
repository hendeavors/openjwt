<?php

namespace Endeavors\OpenJWT\Validator\Concerns;

trait Decoding
{
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    public static function jsonDecode($input)
    {
        return json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
    }
}
