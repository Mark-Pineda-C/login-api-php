<?php
class Database{
    
    // Datos de nuestra base de datos
    private $db_host = 'localhost';
    private $db_name = 'php_auth_api';
    private $db_username = 'root';
    private $db_password = '';
    
    public function dbConnection(){
        
        try{
            $conn = new PDO('mysql:host='.$this->db_host.';dbname='.$this->db_name,$this->db_username,$this->db_password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $conn;
        }
        catch(PDOException $e){
            echo "Error de coneccion ".$e->getMessage(); 
            exit;
        }
          
    }
}
?>