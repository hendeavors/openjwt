<?php

namespace Endeavors\OpenJWT;

use Endeavors\OpenJWT\Validator\InspectionValidator;
use Endeavors\OpenJWT\Validator\AlgorithmValidator;
use Endeavors\OpenJWT\Validator\SignatureValidator;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Endeavors\OpenJWT\Validator\IssuerValidator;
use Endeavors\OpenJWT\Validator\AggregateValidator;
use Endeavors\OpenJWT\JWT;

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

     public static function signed($value, $key)
     {
         $algorithm = new AlgorithmValidator($value);
         $signature =  new SignatureValidator($value, $key);
         $aggregate = (new AggregateValidator)->add($algorithm)->add($signature);

         return JWT::decode($value, $aggregate);
     }

     /**
      * Inspect the JSON web token after validating
      * The algorithm and the audience(aud) claim
      * @param  string $value
      * @param  mixed $audience
      * @return object json decoded payload
      */
     public static function audience($value, ...$audience)
     {
         $algorithm = new AlgorithmValidator($value);
         $audience = new AudienceValidator($value, $audience);
         $aggregate = (new AggregateValidator)->add($algorithm)->add($audience);

         return JWT::decode($value, $aggregate);
     }

     /**
      * Inspect the JSON web token after validating
      * The algorithm and the issuer(iss) claim
      * @param  string $value
      * @param  string $issuer
      * @return object json decoded payload
      */
     public static function issuer($value, string $issuer)
     {
         $algorithm = new AlgorithmValidator($value);
         $issuer = new IssuerValidator($value, $issuer);
         $aggregate = (new AggregateValidator)->add($algorithm)->add($issuer);

         return JWT::decode($value, $aggregate);
     }
}
