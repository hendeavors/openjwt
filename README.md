# openjwt
Inspect or verify a JSON Web Token using various methods.

# Installation

This library requires the use of [Composer](https://getcomposer.org/)

* Require this package with composer `composer require endeavors/openjwt`

## Inspecting

There are multiple ways to validate and inspect a JWT.

### Inspecting without any validation:
```php
use Endeavors\OpenJWT\Inspect;
// ...
$jwt = Inspect::jwt('yourjwt');
```

### Inspecting validating the issuer:
```php
use Endeavors\OpenJWT\Inspect;
// ...
$jwt = Inspect::issuer('yourjwt', 'yourissuer');
```
