<?php
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use SimpleCrud\SimpleCrud;
use Defuse\Crypto;

require "../vendor/autoload.php";

session_start();

$clientId = "59fb3493386b4a6f8db44f3df59e5a34";
$clientSecret = "<snip>";

$container = new Slim\Container();
$container["db"] = function () {
    $pdo = new PDO("mysql:host=localhost;dbname=wearify", "root", "PIPPIPDIGIPIPOCEANPIP!!!");
    $db = new SimpleCrud($pdo);
    return $db;
};
$container["clientId"] = function () use ($clientId) {
    return $clientId;
};
$container["clientSecret"] = function () use ($clientSecret) {
    return $clientSecret;
};

$app = new Slim\App($container);
$app->get("/recent/{token}", function (Request $request, Response $response, $args) {
    $data = \Httpful\Request::get("https://api.spotify.com/v1/me/player/recently-played")
        ->expectsJson()
        ->sendsType(\Httpful\Mime::FORM)
        ->body(http_build_query([
            "limit" => "50"
        ]))
        ->addHeader("Authorization", "Bearer " . $args["token"])
        ->send();
    return $response->withJson($data->body);
});
$app->get("/token", function (Request $request, Response $response) {
    $token = str_replace(["+", "/", "="], "", base64_encode(random_bytes(16)));
    $key = str_replace(["+", "/", "="], "", base64_encode(random_bytes(16)));
    $this->db->authorization[] = [
        "token" => $token,
        "hash" => password_hash($key, PASSWORD_DEFAULT)
    ];
    return $response->withJson([
        "token" => $token,
        "key" => $key
    ]);
});
$app->get("/token/{token}", function (Request $request, Response $response, $args) {
    $data = \Httpful\Request::post("https://accounts.spotify.com/api/token")
        ->expectsJson()
        ->sendsType(\Httpful\Mime::FORM)
        ->body(http_build_query([
            "grant_type" => "refresh_token",
            "refresh_token" => $args["token"]
        ]))
        ->addHeader("Authorization", "Basic " . base64_encode($this->clientId . ":" . $this->clientSecret))
        ->send();
    return $response->withJson($data->body);
});
$app->get("/token/{token}/{key}", function (Request $request, Response $response, $args) {
    $row = $this->db->authorization
        ->select()
        ->one()
        ->where("token = :token", [":token" => $args["token"]])
        ->run();
    if (isset($row)) {
        if ($row->code == null) {
            return $response->withStatus(404)->withJson(["error" => "waiting_for_login"]);
        }
        try {
            $code = Crypto\Crypto::decryptWithPassword($row->code, $args["key"]);
            $row->delete();
            $data = \Httpful\Request::post("https://accounts.spotify.com/api/token")
                ->expectsJson()
                ->sendsType(\Httpful\Mime::FORM)
                ->body(http_build_query([
                    "grant_type" => "authorization_code",
                    "code" => $code,
                    "redirect_uri" => "https://wearify.seapip.com/callback"
                ]))
                ->addHeader("Authorization", "Basic " . base64_encode($this->clientId . ":" . $this->clientSecret))
                ->send();
            return $response->withJson($data->body);
        } catch (Crypto\Exception\WrongKeyOrModifiedCiphertextException $e) {
            return $response->withStatus(404)->withJson(["error" => "wrong_key"]);
        } catch (Crypto\Exception\BadFormatException $e) {
            return $response->withStatus(404)->withJson(["error" => "invalid_key_format"]);
        }
    }
    return $response->withStatus(404)->withJson(["error" => "wrong_or_expired_token"]);
});
$app->get("/login/{token}/{key}", function (Request $request, Response $response, $args) {
    $row = $this->db->authorization
        ->select()
        ->one()
        ->where("token = :token", [":token" => $args["token"]])
        ->run();
    if (isset($row)) {
        if (password_verify($args["key"], $row->hash)) {
            $row->hash = null;
            $row->save();
            $_SESSION["token"] = $args["token"];
            $_SESSION["key"] = $args["key"];
            return $response
                ->withStatus(302)
                ->withHeader("Location", "https://accounts.spotify.com/authorize/?" . http_build_query([
                        "client_id" => $this->clientId,
                        "response_type" => "code",
                        "redirect_uri" => "https://wearify.seapip.com/callback",
                        "scope" => join(" ", [
                            "user-read-private",
                            "playlist-read",
                            "playlist-read-private",
                            "user-read-recently-played",
                            "streaming",
                            "user-read-playback-state",
                            "user-modify-playback-state",
							"user-library-read"])
                    ]));
        }
        return $response->withStatus(404)->withJson(["error" => "wrong_key"]);
    }
    return $response->withStatus(404)->withJson(["error" => "wrong_or_expired_token"]);
});
$app->get("/callback", function (Request $request, Response $response) {
    $params = $request->getQueryParams();
    if (isset($params["code"]) && isset($_SESSION["token"]) && isset($_SESSION["key"])) {
        $this->db->authorization
            ->update()
            ->data([
                "code" => Crypto\Crypto::encryptWithPassword($params["code"], $_SESSION["key"])
            ])
            ->where("token = :token", [":token" => $_SESSION["token"]])
            ->run();
        session_destroy();
        return $response;
    }
});
$app->get("/privacy", function (Request $request, Response $response) {
	return $response->withStatus(302)->withHeader("Location", "https://www.spotify.com/legal/privacy-policy/");
});
$app->run();