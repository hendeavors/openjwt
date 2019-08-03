<?php

namespace Endeavors\OpenJWT;

use Endeavors\OpenJWT\Contracts\JWTValidator;

// In the case where the JWS alg is "none", the app must reject any
// claims where the issuer is different from the url of the authorization server. (3.2.2.11)
// The client application receiving the identity token must validate that the audience (aud) claim matches its own client identifier

class JWT
{
    /**
     * [decode description]
     * @param  [type] $jwt       [description]
     * @param  $validator Validate before decoding
     * @return [type]            [description]
     */
     public static function decode($jwt, JWTValidator $validator)
     {
         $tks = explode('.', $jwt);

         if (count($tks) !== 3) {
             throw new UnexpectedValueException('Wrong number of segments');
         }

         list($headers, $payload, $signature) = $tks;

         $validator->validate();
     }
}
