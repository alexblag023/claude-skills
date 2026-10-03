# Rails-контроллер: open redirect — адрес берётся напрямую из params
class SessionsController < ApplicationController
  def after_login
    target = params[:return_to]
    redirect_to(target)
  end
end
