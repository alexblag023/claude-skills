# Sinatra-обработчик: внедрение команд через интерполяцию params в system
require "sinatra"

post "/ping" do
  host = params[:host]
  system("ping -c1 #{host}")
  "ok"
end
