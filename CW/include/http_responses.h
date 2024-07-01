#ifndef HTTP_RESPONSES_H
#define HTTP_RESPONSES_H

// 2xx - Successful responses:
#define HTTP_200 "HTTP/1.1 200 OK\r\n"
// 4xx - Client error responses:
#define HTTP_400 "HTTP/1.1 400 Bad Request\r\n"
#define HTTP_401 "HTTP/1.1 401 Unauthorized\r\n"
#define HTTP_403 "HTTP/1.1 403 Forbidden\r\n"
#define HTTP_404 "HTTP/1.1 404 Not Found\r\n"
#define HTTP_429 "HTTP/1.1 429 Too Many Requests\r\n"
// 5xx - Server error responses:
#define HTTP_501 "HTTP/1.1 501 Not Implemented\r\n"

#endif // HTTP_RESPONSES_H
