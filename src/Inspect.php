<?php

namespace Endeavors\OpenJWT;

// In the case where the JWS alg is "none", the app must reject any
// claims where the issuer is different from the url of the authorization server. (3.2.2.11)
use Endeavors\OpenJWT\Validator\InspectionValidator;
use Endeavors\OpenJWT\Validator\SignatureValidator;
use Endeavors\OpenJWT\JWT;

class Inspect
{
    /**
     * [decode description]
     * @param  [type] $jwt       [description]
     * @param  $validator Validate before decoding
     * @return [type]            [description]
     */
     public static function jwt($value)
     {
         return JWT::decode($value, new InspectionValidator);
     }

     public static function signedJWT($value, $key)
     {
         return JWT::decode($value, new SignatureValidator($value, $key));
     }
}
