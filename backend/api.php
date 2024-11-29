<?php
header("Content-Type: application/json");


// Habilitar CORS
header("Access-Control-Allow-Origin: *"); // Permite qualquer origem
header("Access-Control-Allow-Methods: POST, GET, OPTIONS"); // Permite métodos HTTP como POST, GET e OPTIONS
header("Access-Control-Allow-Headers: Content-Type, Authorization"); // Permite cabeçalhos como Content-Type e Authorization

// Verifique se a requisição é OPTIONS (preflight request) e, se for, retorne 200 sem processar
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit;
}


// Configuração do banco de dados
try {
    $db = new PDO('mysql:host=database;dbname=berserk_db', 'berserk_user', 'berserk_pass');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(["success" => false, "message" => "Database connection failed: " . $e->getMessage()]);
    exit;
}

// Obter a ação a partir da URL
$action = $_GET['action'] ?? '';

// Validar o token de sessão para endpoints protegidos
if (!in_array($action, ['register', 'login'])) {
    $token = $_POST['token'] ?? '';
    $query = $db->prepare("SELECT * FROM players WHERE session_token = ?");
    $query->execute([$token]);
    $player = $query->fetch(PDO::FETCH_ASSOC);

    if (!$player) {
        echo json_encode(["success" => false, "message" => "Invalid or expired session."]);
        exit;
    }
}

// Lógica para executar a ação
switch ($action) {
    case 'protected_action':
        // A esta altura, $player já está validado
        echo json_encode(["success" => true, "message" => "Protected action executed.", "player" => $player]);
        break;

    case 'register':
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';


        if ($username && $password) {
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            $query = $db->prepare("INSERT INTO players (username, password) VALUES (?, ?)");
            try {
                $query->execute([$username, $hashedPassword]);
                echo json_encode(["success" => true, "message" => "Player registered successfully."]);
            } catch (PDOException $e) {
                if ($e->getCode() == 23000) { // Código para duplicação de chave única
                    echo json_encode(["success" => false, "message" => "Username already exists."]);
                } else {
                    echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
                }
            }
        } else {
            echo json_encode(["success" => false, "message" => "Invalid data. Username and password are required."]);
        }
        break;

    case 'login':
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        // Adicione um log para verificar os dados recebidos
        file_put_contents('php://stderr', "Received username: $username, password: $password\n");

        if (!$username || !$password) {
            echo json_encode(["success" => false, "message" => "Invalid data. Username and password are required."]);
            exit;
        }

        if ($username && $password) {
            try {
                $query = $db->prepare("SELECT * FROM players WHERE username = ?");
                $query->execute([$username]);
                $player = $query->fetch(PDO::FETCH_ASSOC);

                if ($player && password_verify($password, $player['password'])) {
                    // Gerar o token de sessão
                    $session_token = bin2hex(random_bytes(32));

                    // Atualizar o token no banco de dados
                    $updateToken = $db->prepare("UPDATE players SET session_token = ? WHERE id = ?");
                    $updateToken->execute([$session_token, $player['id']]);

                    // Retornar informações do jogador e o token atualizado
                    unset($player['password']); // Remover senha do retorno
                    $player['session_token'] = $session_token;
                    echo json_encode(["success" => true, "player" => $player]);
                } else {
                    echo json_encode(["success" => false, "message" => "Invalid username or password."]);
                }
            } catch (PDOException $e) {
                echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
            }
        } else {
            echo json_encode(["success" => false, "message" => "Invalid data. Username and password are required."]);
        }
        break;

    default:
        echo json_encode(["success" => false, "message" => "Invalid action."]);
        break;
}
