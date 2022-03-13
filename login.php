<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: access");
header("Access-Control-Allow-Methods: POST");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require __DIR__.'/classes/DB.php';
require __DIR__.'/classes/JWT.php';

function msg($success,$status,$message,$extra = []){
    return array_merge([
        'success' => $success,
        'status' => $status,
        'message' => $message
    ],$extra);
}

$db_connection = new Database();
$conn = $db_connection->dbConnection();

$data = json_decode(file_get_contents("php://input"));
$returnData = [];

// Si la mtodo del request no es POST
if($_SERVER["REQUEST_METHOD"] != "POST"):
    $returnData = msg(0,404,'Pagina no encontrada!');

// Revisar campos vacios
elseif(!isset($data->email) 
    || !isset($data->password)
    || empty(trim($data->email))
    || empty(trim($data->password))
    ):

    $fields = ['fields' => ['email','password']];
    $returnData = msg(0,422,'Porfaovr llena los campos requeridos!',$fields);

// Si no hay campos vacios
else:
    $email = trim($data->email);
    $password = trim($data->password);

    // Validamos el formato de correo
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)):
        $returnData = msg(0,422,'Correo electronico invalido!');
    
    // Validamos el tamaño de la contraseña
    elseif(strlen($password) < 8):
        $returnData = msg(0,422,'Contraseña invalida!');

    // Encontes el usuario puede ejecutar la accion de login
    else:
        try{
            
            $fetch_user_by_email = "SELECT * FROM `users` WHERE `email`=:email";
            $query_stmt = $conn->prepare($fetch_user_by_email);
            $query_stmt->bindValue(':email', $email,PDO::PARAM_STR);
            $query_stmt->execute();

            // Si el usuario es encontrado via email
            if($query_stmt->rowCount()):
                $row = $query_stmt->fetch(PDO::FETCH_ASSOC);
                $check_password = password_verify($password, $row['password']);

                // Validamos que la contraseña sea correcta
                // En caso de ser correcto se devuelve el token
                if($check_password):

                    $jwt = new JwtHandler();
                    $token = $jwt->jwtEncodeData(
                        'http://localhost/php_auth_api/',
                        array("user_id"=> $row['id'])
                    );
                    
                    $returnData = [
                        'success' => 1,
                        'message' => 'Has iniciado sesion correctamente.',
                        'token' => $token
                    ];

                // Si la contraseña es incorrecta
                else:
                    $returnData = msg(0,422,'Contraseña invalida!');
                endif;

            // Si el usuario no es encontrado via email
            else:
                $returnData = msg(0,422,'Correo electronico invalido!');
            endif;
        }
        catch(PDOException $e){
            // En caso de ocurrir un error de servidor
            $returnData = msg(0,500,$e->getMessage());
        }

    endif;

endif;

echo json_encode($returnData);
?>