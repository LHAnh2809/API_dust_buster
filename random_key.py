import secrets

# Tạo một khóa bí mật ngẫu nhiên với độ dài 32 ký tự
random_secret_key = secrets.token_hex(16)  # 16 bytes, mỗi byte 2 ký tự hex

print("Random Secret Key:", random_secret_key)
