require "vtapi/version"

require 'rest-client'
require 'json'

class VtAPI
  # 204 exceed the public API request rate limit
  class ExceedAPILimit < StandardError; end
  # 403 Forbidden
  class AuthError < StandardError; end
  # base URL of the VirusTotal Public API v2.0 
  BASE_URL = 'https://www.virustotal.com/vtapi/v2/'
    
  attr_reader :apikey

  def initialize(apikey)
    @apikey = apikey
  end

  def file_scan(data)
    http_post('file/scan', data: data, multipart: true)
  end

  def file_report(resource)
    http_post('file/report', resource: resource)
  end


  def http_post(path, params = {})
    uri = BASE_URL + path
    params['apikey'] = @apikey
    resp = RestClient.post(uri, params) do |resp, req, result, &block|
      case resp.code
      when 204
        raise ExceedAPILimit, "you exceed the public API request rate limit: key[#{@apikey}]"
      when 403
        raise AuthError, "you do not have the required priviledges: key[#{@apikey}]"
      else
        resp.return!(req, result, &block)
      end
    end
    JSON.parse(resp)
  end
end
