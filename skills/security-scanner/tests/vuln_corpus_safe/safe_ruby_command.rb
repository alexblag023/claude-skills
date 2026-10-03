# Безопасно: фиксированная команда + аргумент отдельным элементом argv (без оболочки)
require "sinatra"

post "/ping" do
  host = params[:host]
  system("ping", "-c1", host)
  "ok"
end
