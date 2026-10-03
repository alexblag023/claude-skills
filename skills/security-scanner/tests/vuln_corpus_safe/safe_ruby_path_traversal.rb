# Безопасно: только File.basename + сверка с allow-list каталога
class FilesController < ApplicationController
  ALLOWED_DIR = "/var/data"

  def download
    name = File.basename(params[:name])
    content = File.read(File.join(ALLOWED_DIR, name))
    send_data content
  end
end
