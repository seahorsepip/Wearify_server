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
$container["clientId"] = function () use ($clientId) {
    return $clientId;
};
$container["clientSecret"] = function () use ($clientSecret) {
    return $clientSecret;
};

$app = new Slim\App($container);
$app->get("/token", function (Request $request, Response $response) {
    $token = str_replace(["+", "/", "="], "", base64_encode(random_bytes(16)));
    $key = str_replace(["+", "/", "="], "", base64_encode(random_bytes(16)));
    apc_store($token . "hash", password_hash($key, PASSWORD_DEFAULT), 300);
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
    $code_encrypted = apc_fetch($args["token"] . "code");
    if (!$code_encrypted) {
        return $response->withStatus(404)->withJson(["error" => "waiting_for_login"]);
    }
    apc_delete($args["token"] . "code");
    try {
        $code = Crypto\Crypto::decryptWithPassword($code_encrypted, $args["key"]);
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
    return $response->withStatus(404)->withJson(["error" => "wrong_or_expired_token"]);
});
$app->get("/login/{token}/{key}", function (Request $request, Response $response, $args) {
    $hash = apc_fetch($args["token"] . "hash");
    if ($hash) {
        if (password_verify($args["key"], $hash)) {
            apc_delete($token . "hash");
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
        apc_store($_SESSION["token"] . "code", Crypto\Crypto::encryptWithPassword($params["code"], $_SESSION["key"]), 300);
        session_destroy();
        return $response;
    }
});
$app->run();
