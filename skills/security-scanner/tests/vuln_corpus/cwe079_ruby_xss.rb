# Rails-хелпер: XSS — данные запроса помечаются html_safe и выводятся без экранирования
class CommentsController < ApplicationController
  def show
    comment = params[:comment]
    @html = raw(comment)
    render inline: @html
  end
end
