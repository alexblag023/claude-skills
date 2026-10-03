# Sinatra-обработчик: небезопасная десериализация тела запроса через YAML.load
require "yaml"
require "sinatra"

post "/import" do
  data = YAML.load(request.body.read)
  data.inspect
end
