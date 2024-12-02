<?php
header("Content-Type: application/json");

// Habilitar CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

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
                if ($e->getCode() == 23000) {
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
                    $session_token = bin2hex(random_bytes(32));

                    $updateToken = $db->prepare("UPDATE players SET session_token = ? WHERE id = ?");
                    $updateToken->execute([$session_token, $player['id']]);

                    unset($player['password']);
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
    case 'add_experience':
        // Recebe o token de sessão e a quantidade de experiência a ser adicionada
        $token = $_POST['token'] ?? '';
        $experience_to_add = $_POST['experience'] ?? 0;

        // Verifica se o token é válido e obtém os dados do jogador
        $query = $db->prepare("SELECT * FROM players WHERE session_token = ?");
        $query->execute([$token]);
        $player = $query->fetch(PDO::FETCH_ASSOC);

        if (!$player) {
            echo json_encode(["success" => false, "message" => "Invalid or expired session."]);
            exit;
        }

        // Adiciona a experiência ao jogador
        $new_experience = $player['experience'] + $experience_to_add;

        // Obtém o nível correspondente à experiência
        $level_query = $db->prepare("SELECT * FROM levels WHERE experience_needed <= ? ORDER BY experience_needed DESC LIMIT 1");
        $level_query->execute([$new_experience]);
        $level = $level_query->fetch(PDO::FETCH_ASSOC);

        if ($level) {
            $new_level = $level['level'];
        } else {
            // Se não encontrar nível correspondente, manter o nível atual
            $new_level = $player['level'];
        }

        // Atualiza o banco de dados com o novo nível e a nova quantidade de experiência
        $update = $db->prepare("UPDATE players SET level = ?, experience = ? WHERE id = ?");
        $update->execute([$new_level, $new_experience, $player['id']]);

        echo json_encode([
            "success" => true,
            "message" => "Experience updated and level recalculated.",
            "level" => $new_level,
            "experience" => $new_experience
        ]);
        break;

    case 'player_info':
        $token = $_POST['token'] ?? '';

        // Verifica o token e obtém os dados do jogador
        $query = $db->prepare("SELECT * FROM players WHERE session_token = ?");
        $query->execute([$token]);
        $player = $query->fetch(PDO::FETCH_ASSOC);

        if (!$player) {
            echo json_encode(["success" => false, "message" => "Invalid or expired session."]);
            exit;
        }

        // Recupera as missões do jogador
        $missionsQuery = $db->prepare("SELECT * FROM player_missions WHERE player_id = ?");
        $missionsQuery->execute([$player['id']]);
        $missions = $missionsQuery->fetchAll(PDO::FETCH_ASSOC);

        // Retorna os dados do jogador junto com as missões
        echo json_encode(["success" => true, "player" => $player, "missions" => $missions]);
        break;


    case 'create_mission':
        $name = $_POST['name'] ?? '';
        $description = $_POST['description'] ?? '';
        $experience_reward = $_POST['experience_reward'] ?? 0;

        if ($name && $experience_reward) {
            try {
                $query = $db->prepare("INSERT INTO missions (name, description, experience_reward) VALUES (?, ?, ?)");
                $query->execute([$name, $description, $experience_reward]);
                echo json_encode(["success" => true, "message" => "Mission created successfully."]);
            } catch (PDOException $e) {
                echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
            }
        } else {
            echo json_encode(["success" => false, "message" => "Invalid data. Name and experience reward are required."]);
        }
        break;

    // Exemplo de ação 'assign_mission'
    case 'assign_mission':
        $token = $_POST['token'] ?? '';
        $mission_id = $_POST['mission_id'] ?? 0;

        // Verifica o token de sessão e obtém os dados do jogador
        $query = $db->prepare("SELECT * FROM players WHERE session_token = ?");
        $query->execute([$token]);
        $player = $query->fetch(PDO::FETCH_ASSOC);

        if (!$player) {
            echo json_encode(["success" => false, "message" => "Invalid or expired session."]);
            exit;
        }

        // Verifica se a missão existe
        $mission_query = $db->prepare("SELECT * FROM missions WHERE id = ?");
        $mission_query->execute([$mission_id]);
        $mission = $mission_query->fetch(PDO::FETCH_ASSOC);

        if (!$mission) {
            echo json_encode(["success" => false, "message" => "Mission not found."]);
            exit;
        }

        // Atribui a missão ao jogador
        $insert_query = $db->prepare("INSERT INTO player_missions (player_id, mission_id) VALUES (?, ?)");
        $insert_query->execute([$player['id'], $mission_id]);

        echo json_encode(["success" => true, "message" => "Mission assigned to player."]);
        break;


    case 'complete_mission':
        $token = $_POST['token'] ?? '';
        $mission_id = $_POST['mission_id'] ?? 0;

        // Verifica o token de sessão e obtém os dados do jogador
        $query = $db->prepare("SELECT * FROM players WHERE session_token = ?");
        $query->execute([$token]);
        $player = $query->fetch(PDO::FETCH_ASSOC);

        if (!$player) {
            echo json_encode(["success" => false, "message" => "Invalid or expired session."]);
            exit;
        }

        // Verifica se a missão está atribuída ao jogador
        $mission_query = $db->prepare("SELECT * FROM player_missions WHERE player_id = ? AND mission_id = ?");
        $mission_query->execute([$player['id'], $mission_id]);
        $mission = $mission_query->fetch(PDO::FETCH_ASSOC);

        if (!$mission) {
            echo json_encode(["success" => false, "message" => "Mission not assigned to player."]);
            exit;
        }

        // Marca a missão como completada
        $update_query = $db->prepare("UPDATE player_missions SET status = 'completed' WHERE player_id = ? AND mission_id = ?");
        $update_query->execute([$player['id'], $mission_id]);

        // Adiciona a experiência ao jogador
        $mission_details = $db->prepare("SELECT * FROM missions WHERE id = ?");
        $mission_details->execute([$mission_id]);
        $mission_data = $mission_details->fetch(PDO::FETCH_ASSOC);

        $new_experience = $player['experience'] + $mission_data['experience_reward'];

        // Atualiza o jogador com a nova experiência
        $update_experience = $db->prepare("UPDATE players SET experience = ? WHERE id = ?");
        $update_experience->execute([$new_experience, $player['id']]);

        echo json_encode(["success" => true, "message" => "Mission completed, experience added."]);
        break;


    default:
        echo json_encode(["success" => false, "message" => "Invalid action."]);
        break;
}
