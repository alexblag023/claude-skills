# Rails-контроллер: SQL-инъекция через интерполяцию params в where
class UsersController < ApplicationController
  def search
    name = params[:name]
    @users = User.where("name = '#{name}'")
    render json: @users
  end
end
