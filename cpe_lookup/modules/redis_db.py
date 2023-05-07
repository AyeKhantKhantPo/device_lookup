from typing import Dict

import redis


class RedisClient:
    __slots__ = ("redis_dsn", "redis_pwd", "db", "socket_timeout", "redis_client")

    def __init__(
        self,
        redis_dsn: str,
        redis_pwd: str = None,
        db: int = None,
        socket_timeout: int = 10,
    ):
        self.redis_dsn = redis_dsn
        self.redis_pwd = redis_pwd
        self.socket_timeout = socket_timeout
        self.db = db
        self.redis_client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self) -> None:
        self.redis_client = redis.StrictRedis.from_url(
            self.redis_dsn,
            password=self.redis_pwd,
            db=self.db,
            decode_responses=True,
            socket_keepalive=True,
            socket_timeout=self.socket_timeout,
        )

    def set_data(self, key, expire, value) -> None:
        if self.redis_client is None:
            self.connect()

        self.redis_client.setex(key, expire, value)

    def get_data(self, key) -> Dict:
        if self.redis_client is None:
            self.connect()

        return self.redis_client.get(key)

    def del_data(self, key) -> None:
        if self.redis_client is None:
            self.connect()

        self.redis_client.delete(key)

    def is_exist(self, key) -> None:
        if self.redis_client is None:
            self.connect()

        return self.redis_client.exists(key)
