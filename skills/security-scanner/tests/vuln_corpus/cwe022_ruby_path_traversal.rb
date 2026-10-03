# Rails-контроллер: обход пути — имя файла из params без очистки
class FilesController < ApplicationController
  def download
    name = params[:name]
    content = File.read("/var/data/" + name)
    send_data content
  end
end
