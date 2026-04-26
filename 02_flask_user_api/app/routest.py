#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
import uuid
import hashlib

app = Flask(__name__)

# 简易数据库
users = {}          # user_id -> user_info
tokens = {}         # token -> user_id


def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()


def generate_token():
    return uuid.uuid4().hex


# -------------------------
# 注册
# -------------------------
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    account = data.get("account")
    password = data.get("password")

    if not account or not password:
        return jsonify({"error": "account and password required"}), 400

    # 检查是否重复
    for u in users.values():
        if u["account"] == account:
            return jsonify({"error": "account exists"}), 400

    user_id = str(len(users) + 1)
    users[user_id] = {
        "id": user_id,
        "account": account,
        "password": hash_password(password)
    }

    # 注册后自动登录
    token = generate_token()
    tokens[token] = user_id

    return jsonify({"id": user_id, "token": token}), 201


# -------------------------
# 登录
# -------------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    account = data.get("account")
    password = data.get("password")

    for user_id, info in users.items():
        if info["account"] == account and info["password"] == hash_password(password):
            token = generate_token()
            tokens[token] = user_id
            return jsonify({"token": token}), 200

    return jsonify({"error": "invalid credentials"}), 401


# -------------------------
# 鉴权装饰器
# -------------------------
def require_token(func):
    def wrapper(*args, **kwargs):
        token = request.headers.get("Token")
        if not token or token not in tokens:
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


# -------------------------
# 查询用户信息
# -------------------------
@app.route('/user/<user_id>', methods=['GET'])
@require_token
def get_user(user_id):
    if user_id not in users:
        return jsonify({"error": "not found"}), 404
    return jsonify(users[user_id]), 200


# -------------------------
# 删除用户
# -------------------------
@app.route('/user/<user_id>', methods=['DELETE'])
@require_token
def delete_user(user_id):
    if user_id not in users:
        return jsonify({"error": "not found"}), 404
    del users[user_id]
    return jsonify({"message": "deleted"}), 200


# -------------------------
# 退出登录
# -------------------------
@app.route('/logout', methods=['POST'])
@require_token
def logout():
    token = request.headers.get("Token")
    tokens.pop(token, None)
    return jsonify({"message": "logged out"}), 200


if __name__ == '__main__':
    app.run(debug=True)
  
