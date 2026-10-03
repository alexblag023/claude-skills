# Безопасно: YAML.safe_load разрешает только примитивные типы (без произвольных объектов)
require "yaml"
require "sinatra"

post "/import" do
  data = YAML.safe_load(request.body.read)
  data.inspect
end
