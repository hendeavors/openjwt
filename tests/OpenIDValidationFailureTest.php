<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\OpenIDToken;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Firebase\JWT\JWT;

class OpenIDValidationFailureTest extends TestCase
{
    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage  An authorized party claim must be present
     */
    public function authorizedPartyClaimMustBePresent()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $token = OpenIDToken::create($jwt)
        ->requestedAt(time())
        ->client("http://example.com", "http://google.com")
        ->server("http://example.org")
        ->decode();
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage The audience claim received does not match the given set of audiences
     */
    public function audienceExactMatch()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://google.com", "http://example.com"],
            "azp" => ["http://example.com", "http://google.com"],
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $token = OpenIDToken::create($jwt)
        ->requestedAt(time())
        ->client("http://example.com", "http://google.com")
        ->server("http://example.org")
        ->decode();
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage The authorized party received does not match the given set of audiences
     */
    public function authorizedPartyExactMatch()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => ["http://google.com", "http://example.com"],
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $token = OpenIDToken::create($jwt)
        ->requestedAt(time())
        ->client("http://example.com", "http://google.com")
        ->server("http://example.org")
        ->decode();
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage  The authorized party received does not match the given set of audiences
     */
    public function invalidAuthorizedPartyClaimPresent()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => "foo",
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $token = OpenIDToken::create($jwt)
        ->requestedAt(time())
        ->client("http://example.com", "http://google.com")
        ->server("http://example.org")
        ->decode();
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage  The authorized party claim is not valid
     */
    public function nullAuthorizedPartyClaimPresent()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => null,
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $token = OpenIDToken::create($jwt)
        ->requestedAt(time())
        ->client("http://example.com", "http://google.com")
        ->server("http://example.org")
        ->decode();
    }
}
