<?php

namespace Endeavors\OpenJWT;

use Endeavors\OpenJWT\Validator\InspectionValidator;
use Endeavors\OpenJWT\Validator\AlgorithmValidator;
use Endeavors\OpenJWT\Validator\SignatureValidator;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Endeavors\OpenJWT\Validator\IssuerValidator;
use Endeavors\OpenJWT\Validator\AuthorizedPartyValidator;
use Endeavors\OpenJWT\Validator\AggregateValidator;
use Endeavors\OpenJWT\JWT;
use Closure;

class Inspect
{
    /**
     * Inspect the JSON Web Token
     * @param  string $value
     * @return object json decoded payload
     */
     public static function jwt($value)
     {
         return JWT::decode($value, new InspectionValidator);
     }

     /**
      * Inspect the JSON web token after validating
      * The signature
      * @param  string $value
      * @param  mixed $key
      * @return object json decoded payload
      * @todo needs testing
      */
     public static function signed($value, $key)
     {
         return JWT::decode($value, new SignatureValidator($value, $key));
     }

     /**
      * Inspect the JSON web token after validating
      * The audience(aud) claim
      * @param  string $value
      * @param  mixed $audience
      * @return object json decoded payload
      */
     public static function audience($value, ...$audience)
     {
         return JWT::decode($value, new AudienceValidator($value, $audience));
     }

     /**
      * Inspect the JSON web token after validating
      * The authorized party claim(azp)
      * @param  string $value
      * @param  mixed $audience
      * @return object json decoded payload
      */
     public static function authorized($value, ...$audience)
     {
         return JWT::decode($value, new AuthorizedPartyValidator($value, $audience));
     }

     /**
      * Inspect the JSON web token after validating
      * The issuer(iss) claim
      * @param  string $value
      * @param  string $issuer
      * @return object json decoded payload
      */
     public static function issuer($value, string $issuer)
     {
         return JWT::decode($value, new IssuerValidator($value, $issuer));
     }

     /**
      * Combine a set of validators using the AggregateValidator
      * @param  string  $value   the token
      * @param  Closure $callback Validators to aggregate
      * @return object json decoded payload
      */
     public static function aggregate($value, Closure $callback)
     {
         return JWT::decode($value, $callback(new AggregateValidator, $value));
     }
}
