import requests
data = {
    'uid': '0887d14fbe253e8b6a7b8193f3891e04f88a9ed744b91f4990d567ffc8b18e5f',
    'message': '57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32',
    'proof': {
        "auth_id": 0,
        "message_body": "S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH",
        "user_payload": '{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}',
        "account_id": "keys.auth.hot.tg"
    }
}
for _ in range(5):
    import time

    start = time.time()
    res = requests.post('http://localhost:20000/sign', json=data)
    end = time.time()
    print(end - start)
    print(res.text)
