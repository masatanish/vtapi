require 'json'
require 'time'

class VtAPI
  class Response
    def initialize(response_body)
      @json = JSON.parse(response_body)
      @json.keys.each do |key|
        Response.class_eval {
          define_method key.to_s do |*args|
            @json[key]
          end
        }
      end
      if @json.has_key? 'scan_date'
        @json['scan_date'] = Time.parse(@json['scan_date'] + "UTC")
      end
    end

    def keys
      @json.keys
    end

    def positive_threats
      Hash[@json.fetch('scans', {}).select{|k,v| v['detected'] }.map{|k,v| [k, v['result']] }]
    end

    def positive_brands
      @json.fetch('scans', {}).select{|k,v| v['detected'] }.keys
    end

    def [](key)
      @json.fetch(key.to_s) # raise KeyError when key doesn't exist.
    end
  end
end
