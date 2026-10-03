# Безопасно: ввод экранируется перед выводом (ERB::Util.html_escape), html_safe не применяется
class CommentsController < ApplicationController
  def show
    comment = params[:comment]
    @html = ERB::Util.html_escape(comment)
    render inline: @html
  end
end
