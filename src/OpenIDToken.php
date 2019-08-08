<?php

namespace Endeavors\OpenJWT;

use Endeavors\OpenJWT\JWT;
use Endeavors\OpenJWT\Validator\InspectionValidator;
use Endeavors\OpenJWT\Validator\AlgorithmValidator;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Endeavors\OpenJWT\Validator\IssuerValidator;
use Endeavors\OpenJWT\Validator\IssuedAtValidator;
use Endeavors\OpenJWT\Validator\AuthorizedPartyValidator;
use Endeavors\OpenJWT\Validator\SignatureValidator;
use Endeavors\OpenJWT\Validator\AggregateValidator;
use LogicException;

class OpenIDToken
{
    private $validator;

    private $claims = [];

    public function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function create($value)
    {
        return new static($value);
    }

    public function signed($key, $algorithm = 'RS256')
    {
        if (null === $this->validator) {
            $this->validator = new AggregateValidator();
        }

        $this->validator->add(new SignatureValidator($this->value, $key, $algorithm));

        return $this;
    }

    public function client(...$audience)
    {
        if (null === $this->validator) {
            $this->validator = new AggregateValidator();
        }

        $this->claims[] = 'aud';

        $this->validator->add(new AudienceValidator($this->value, $audience));

        return $this;
    }

    public function provider($issuer)
    {
        if (null === $this->validator) {
            $this->validator = new AggregateValidator();
        }

        $this->claims[] = 'iss';

        $this->validator->add(new IssuerValidator($this->value, $issuer));

        return $this;
    }

    public function requestedAt(int $time)
    {
        if (null === $this->validator) {
            $this->validator = new AggregateValidator();
        }

        $this->claims[] = 'iat';

        $this->validator->add(new IssuedAtValidator($this->value, $time));

        return $this;
    }

    public function decode()
    {
        if (null === $this->validator) {
            throw new LogicException("Validation requirements must be met prior to decoding id token.");
        }

        $claims = ['iat', 'iss', 'aud'];
        // we don't care about order here
        if (sort($claims) != sort($this->claims)) {
            throw new LogicException(sprintf("Validation for claims %s are required prior to decoding id token.", json_encode(array_values(array_diff($claims, $this->claims)))));
        }

        $this->validator->add(new AlgorithmValidator($this->value));

        return JWT::decode($this->value, $this->validator);
    }
}
