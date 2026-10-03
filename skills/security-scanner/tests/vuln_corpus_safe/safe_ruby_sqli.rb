# Безопасно: параметризованный where с плейсхолдером ? — ввод идёт биндом, не частью SQL
class UsersController < ApplicationController
  def search
    name = params[:name]
    @users = User.where("name = ?", name)
    render json: @users
  end
end
