# Безопасно: ввод отображается в allow-list внутренних путей; сырой адрес в redirect_to не попадает
class SessionsController < ApplicationController
  def after_login
    path = case params[:return_to]
           when "profile" then "/profile"
           when "settings" then "/settings"
           else "/"
           end
    redirect_to(path, only_path: true)
  end
end
