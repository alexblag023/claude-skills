# Безопасно: пароль хешируется bcrypt (адаптивная соль+стоимость), не MD5/SHA1
require "bcrypt"

class PasswordHasher
  def hash_password(password)
    BCrypt::Password.create(password)
  end
end
