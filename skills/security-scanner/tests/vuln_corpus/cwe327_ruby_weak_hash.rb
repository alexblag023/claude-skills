# Слабое хеширование пароля через MD5 (CWE-327)
require "digest"

class PasswordHasher
  def hash_password(password)
    Digest::MD5.hexdigest(password)
  end
end
