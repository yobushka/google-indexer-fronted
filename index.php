<?php

// Функция для кодирования в base64 URL
function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// Если форма отправлена
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['urls']) && !empty($_FILES['service_account']['tmp_name'])) {
    $urls = array_filter(array_map('trim', explode("\n", $_POST['urls'])));
    $serviceAccountFileContent = file_get_contents($_FILES['service_account']['tmp_name']);
    $creds = json_decode($serviceAccountFileContent, true);

    function getAccessToken($creds) {
        $now = time();
        $jwtHeader = ['alg' => 'RS256', 'typ' => 'JWT'];
        $jwtClaimSet = [
            'iss' => $creds['client_email'],
            'scope' => 'https://www.googleapis.com/auth/indexing',
            'aud' => 'https://oauth2.googleapis.com/token',
            'iat' => $now,
            'exp' => $now + 3600,
        ];

        $jwtHeaderEnc = base64UrlEncode(json_encode($jwtHeader));
        $jwtClaimEnc = base64UrlEncode(json_encode($jwtClaimSet));
        $jwtUnsigned = "$jwtHeaderEnc.$jwtClaimEnc";

        $privateKey = openssl_pkey_get_private($creds['private_key']);
        openssl_sign($jwtUnsigned, $signature, $privateKey, 'sha256WithRSAEncryption');
        $jwtSigned = $jwtUnsigned . '.' . base64UrlEncode($signature);

        $ch = curl_init('https://oauth2.googleapis.com/token');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-type: application/x-www-form-urlencoded']);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwtSigned,
        ]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        curl_close($ch);

        $data = json_decode($result, true);
        return $data['access_token'] ?? null;
    }

    $token = getAccessToken($creds);

    if (!$token) {
        echo "<p style='color:red'>Ошибка: не удалось получить access token.</p>";
        exit;
    }

    echo "<h3>Результаты отправки:</h3><pre>";
    foreach ($urls as $url) {
        $payload = json_encode([
            'url' => $url,
            'type' => 'URL_UPDATED',
        ]);

        $ch = curl_init('https://indexing.googleapis.com/v3/urlNotifications:publish');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Content-type: application/json",
            "Authorization: Bearer $token",
        ]);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $res = curl_exec($ch);
        curl_close($ch);

        $json = json_decode($res, true);
        echo "$url → " . ($json['notifyTime'] ?? 'Ошибка') . "\n";
    }
    echo "</pre>";
}

?>

<!-- HTML-форма -->
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Google Indexing API – Отправка URL</title>
  <style>
    body { font-family: sans-serif; padding: 2em; max-width: 600px; margin: auto; }
    textarea { width: 100%; height: 200px; margin-top: 10px; }
    input[type="submit"] { margin-top: 10px; }
    pre { background: #eee; padding: 1em; white-space: pre-wrap; }
  </style>
</head>
<body>
  <h2>Google Indexing API – Отправка URL</h2>
  <form method="POST" enctype="multipart/form-data">
    <label>Загрузите файл service-account.json:</label><br>
    <input type="file" name="service_account" accept=".json" required><br><br>
    <label>Введите список URL (по одному на строке):</label><br>
    <textarea name="urls"><?php echo htmlspecialchars($_POST['urls'] ?? ''); ?></textarea><br>
    <input type="submit" value="Отправить в Indexing API">
  </form>
</body>
</html>
