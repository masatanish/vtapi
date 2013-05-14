class VtAPI
  # 204 exceed the public API request rate limit
  class ExceedAPILimit < StandardError; end
  # 403 Forbidden
  class AuthError < StandardError; end
end
