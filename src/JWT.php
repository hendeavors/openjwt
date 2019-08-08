<?php

namespace Endeavors\OpenJWT;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Validator\Concerns\Decoding;
use UnexpectedValueException;

class JWT
{
    use Decoding;
    /**
     * Decodes a payload given from a JWT
     * @param  string $jwt The token
     * @param  $validator Validate before decoding
     * @return object
     */
     public static function decode($jwt, JWTValidator $validator)
     {
         $tks = explode('.', $jwt);

         if (count($tks) !== 3) {
             throw new UnexpectedValueException('Wrong number of segments');
         }

         list($headers, $payload, $signature) = $tks;

         $validator->validate();

         return static::jsonDecode(static::urlsafeB64Decode($payload));
     }
}
