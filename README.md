DOC DO PROJETO PARA FUTUROS USOS 

composer create-project --prefer-dist laravel/laravel jwt-auth
cd jwt-auth

composer require tymon/jwt-auth
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
php artisan jwt:secret


SEC EM BASE DE JWT 

JÁ EXISTENTE 
LOGIN
CADASTRAR
LOGOUT


SENHA 
MIN 8 CARACTERES 
1 letra Maiscula 
1 letra Minuscula 
1 caractere especial


OQUE FOI ALTERADO 
AUTHCONTROLLER 
CORS
AUTETICATOR 
AUTH
API
MODEL 
DATABASE

