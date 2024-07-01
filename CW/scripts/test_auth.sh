#!/bin/bash

USERNAME="test"
PASSWORD="password"
URI="/private"
SERVER="http://127.0.0.1:8080"

# Функция для выполнения запроса с авторизацией Digest
perform_request() {
    local nonce="$1"
    local realm="$2"
    local algorithm="$3"
    local opaque="$4"
    local qop="$5"

    # Генерация cnonce и увеличение NC
    local cnonce="$(openssl rand -hex 8)"
    local nc="00000001"  # Начальное значение NC в шестнадцатеричном формате

    # Функция для вычисления MD5 хеша
    md5() {
        echo -n "$1" | md5sum | awk '{print $1}'
    }

    # Вычисление ha1 и ha2
    ha1="$(md5 "$USERNAME:$realm:$PASSWORD")"
    ha2="$(md5 "GET:$URI")"

    # Формирование response
    response="$(printf "%s:%s:%s:%s:%s:%s" "$ha1" "$nonce" "$nc" "$cnonce" "$qop" "$ha2")"
    response="$(md5 "$response")"

    # Формирование заголовка авторизации
    auth_header="Digest username=\"$USERNAME\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$URI\", algorithm=$algorithm, response=\"$response\", opaque=\"$opaque\", qop=$qop, nc=$nc, cnonce=\"$cnonce\""

    # Логирование отправки запроса
    echo "Sending request to $SERVER$URI with Authorization: $auth_header"

    # Выполнение запроса с curl и логирование ответа
    response=$(curl -s -v --header "Authorization: $auth_header" "$SERVER$URI" 2>&1)

    # Увеличение NC для следующего запроса
    nc_hex="$(printf "%08x" "$(( 16#${nc} + 1 ))")"
    nc="${nc_hex^^}"  # Перевод в верхний регистр для использования в response

    if echo "$response" | grep -q "HTTP/1.1 401 Unauthorized"; then
        echo "Received 401 Unauthorized, retrying..."
        perform_request "$nonce" "$realm" "$algorithm" "$opaque" "$qop"
    else
        echo "Response:"
        echo "$response"
    fi
}

# Начало выполнения запроса
response_header=$(curl -s -i "$SERVER$URI" | grep -i "WWW-Authenticate")
echo "Get response from $SERVER$URI with WWW-Authorization: $response_header"
echo

if [[ "$response_header" =~ nonce=\"([^\"]+)\" ]]; then
    nonce="${BASH_REMATCH[1]}"
fi

if [[ "$response_header" =~ realm=\"([^\"]+)\" ]]; then
    realm="${BASH_REMATCH[1]}"
fi

if [[ "$response_header" =~ algorithm=([a-zA-Z0-9]+), ]]; then
    algorithm="${BASH_REMATCH[1]}"
fi

if [[ "$response_header" =~ opaque=\"([^\"]+)\" ]]; then
    opaque="${BASH_REMATCH[1]}"
fi

if [[ "$response_header" =~ qop=([a-z]+), ]]; then
    qop="${BASH_REMATCH[1]}"
fi

sleep 3

# Запуск функции с параметрами из ответа сервера
perform_request "$nonce" "$realm" "$algorithm" "$opaque" "$qop"
