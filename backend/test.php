<?php
try {
    $db = new PDO('mysql:host=database;dbname=berserk_db', 'berserk_user', 'berserk_pass');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo json_encode(["success" => true, "message" => "Database connection successful."]);
} catch (PDOException $e) {
    echo json_encode(["success" => false, "message" => "Database connection failed: " . $e->getMessage()]);
}
