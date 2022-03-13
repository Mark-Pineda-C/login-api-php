<?php
require './vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\key;

class JwtHandler
{
    protected $jwt_secrect;
    protected $token;
    protected $issuedAt;
    protected $expire;
    protected $jwt;

    public function __construct()
    {
        // definimos nuestra zona horaria
        date_default_timezone_set('America/Lima');
        $this->issuedAt = time();

        // Definimos el tiempo de validez del token (3600 segundos = 1 hora)
        $this->expire = $this->issuedAt + 3600;

        // Se crea la llave secreta
        $this->jwt_secrect = "esta_es_una_llave_secreta";
    }

    public function jwtEncodeData($iss, $data)
    {

        $this->token = array(
            // Añadimos el identificador al token.
            "iss" => $iss,
            "aud" => $iss,
            // Añadimos la marca de tiempo al token, para poder identificar el momento de creacion.
            "iat" => $this->issuedAt,
            // Expiracion del token.
            "exp" => $this->expire,
            // Payload
            "data" => $data
        );

        $this->jwt = JWT::encode($this->token, $this->jwt_secrect, 'HS256');
        return $this->jwt;
    }

    public function jwtDecodeData($jwt_token)
    {
        try {
            $decode = JWT::decode($jwt_token, new key($this->jwt_secrect, 'HS256'));
            return [
                "data" => $decode->data
            ];
        } catch (Exception $e) {
            return [
                "message" => $e->getMessage()
            ];
        }
    }
}
?>